/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.tests.*
import com.android.build.gradle.internal.tasks.*
import org.jetbrains.kotlin.gradle.*
import org.jetbrains.kotlin.gradle.plugin.*
import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.gradle.targets.js.ir.*
import org.jetbrains.kotlin.gradle.targets.js.testing.*
import org.jetbrains.kotlin.gradle.targets.jvm.tasks.*
import org.jetbrains.kotlin.gradle.targets.native.tasks.*
import org.gradle.kotlin.dsl.*
import java.io.File
import dev.whyoleg.cryptography.testtool.plugin.TesttoolServerConfiguration
import dev.whyoleg.cryptography.testtool.plugin.TesttoolServerService

plugins {
    id("ckbuild.multiplatform-base")
}

// https://github.com/Kotlin/kotlinx-kover/issues/747
if (project.name != "cryptography-provider-jdk-android-tests") {
    plugins.apply("org.jetbrains.kotlinx.kover")
} else {
    // as we depend on it in the ` jvmAllTest ` task
    tasks.register("koverVerify")
}

@OptIn(ExperimentalKotlinGradlePluginApi::class)
kotlin {
    // just applying `kotlin-test` doesn't work for JVM if there are multiple test tasks (like when we test on different JDKs)
    sourceSets.configureEach {
        when (name) {
            "commonTest" -> "test"
            "jvmTest"    -> "test-junit"
            else         -> null
        }?.let { testDependency ->
            dependencies {
                implementation(kotlin(testDependency))
            }
        }
    }

    targets.withType<KotlinJsIrTarget>().configureEach {
        // Browser tests run via Web Test Runner (Playwright) using :test.
        // We no longer configure Karma for browser tests.
        // Emit ESM for the browser test development executable so Web Test Runner can import it
        project.tasks.matching { it.name == "compileTestDevelopmentExecutableKotlinJs" }
            .withType(org.jetbrains.kotlin.gradle.targets.js.ir.KotlinJsIrLink::class.java)
            .configureEach {
                compilerOptions {
                    moduleKind.set(org.jetbrains.kotlin.gradle.dsl.JsModuleKind.MODULE_ES)
                }
            }

        // Provide a generic :test task to run browser tests via Web Test Runner (Playwright)
        whenBrowserConfigured {
            if (project.tasks.findByName("test") == null) {
                // Placeholder for potential Testtool server wiring if needed
                val testtoolConfig = TesttoolServerConfiguration(rootProject)
                // Keep server alive while WTR runs by using the BuildService directly
                val wtrServerService = gradle.sharedServices.registerIfAbsent(
                    "wtr-testtool-server-service",
                    TesttoolServerService::class.java
                ) {
                    parameters.instanceId.set(providers.gradleProperty("ckbuild.testtool.instanceId").orElse("wtr"))
                    parameters.storage.set(testtoolConfig.serverStorageDir)
                }

                project.tasks.register<org.gradle.api.tasks.Exec>("test") {
                    // This Exec task wires a BuildService and streams output; mark as CC-incompatible
                    notCompatibleWithConfigurationCache("Exec task streams output and uses a BuildService")
                    // Allow skipping per-module WTR when using aggregated browser run
                    onlyIf {
                        !providers.gradleProperty("ckbuild.aggregateJsBrowser")
                            .map(String::toBoolean)
                            .getOrElse(false)
                    }
                    group = org.gradle.language.base.plugins.LifecycleBasePlugin.VERIFICATION_GROUP
                    description = "Run JS browser tests via Web Test Runner (Playwright Chrome)"
                    dependsOn(project.tasks.matching { it.name == "jsTestTestDevelopmentExecutableCompileSync" })
                    // Also tie the server BuildService lifecycle to this Exec task
                    usesService(wtrServerService)
                    // Force service realization so the server actually starts before WTR
                    doFirst {
                        wtrServerService.get()
                    }
                    // Assume browsers are pre-installed (installBrowsers) in CI/local; no hard dependency here
                    workingDir = rootProject.projectDir

                    // Restrict WTR to this module's browser test dev executable
                    val relModuleDir = project.projectDir.relativeTo(rootProject.projectDir)
                        .path.replace(File.separatorChar, '/')
                    val testGlob = "$relModuleDir/build/compileSync/js/test/testDevelopmentExecutable/kotlin/*-test.mjs"

                    // Note: Testtool server is not required for default browser tests; run WTR directly

                    val cmd = listOf(
                        "bash", "-lc",
                        "set -o pipefail; " +
                            "WTR_FILES='$testGlob' pnpm exec web-test-runner --config web-test-runner.config.mjs | tee 'build/wtr-${project.name}.log'; " +
                            "status=${'$'}{PIPESTATUS[0]}; exit ${'$'}status"
                    )
                    commandLine = cmd

                    // If a Testtool server is required, it is started via BuildService before running :test

                    // Optional grep via -Pckbuild.wtrGrep="pattern"
                    val wtrGrep = providers.gradleProperty("ckbuild.wtrGrep").orNull
                    var grepApplied = false
                    wtrGrep?.let { grep ->
                        if (grep.isNotBlank()) {
                            environment("WTR_GREP", grep)
                            grepApplied = true
                        }
                    }
                    // Map providerTests.step to grep if not explicitly set
                    if (!grepApplied) {
                        val step = providers.gradleProperty("ckbuild.providerTests.step").orNull
                        val mapped = when (step) {
                            null -> "^(?:(?!CompatibilityTest.*(generateStep|generateStressStep|validateStep)$).)*$"
                            "compatibility.generate" -> "CompatibilityTest.*generateStep$"
                            "compatibility.generateStress" -> "CompatibilityTest.*generateStressStep$"
                            "compatibility.validate" -> "CompatibilityTest.*validateStep$"
                            else -> null
                        }
                        if (mapped != null) environment("WTR_GREP", mapped)
                    }
                    // Optional live browser logs: -Pckbuild.wtrLogs=true
                    val isCi = System.getenv("CI") != null || System.getenv("GITHUB_ACTIONS") != null
                    val wtrLogs = providers.gradleProperty("ckbuild.wtrLogs").map(String::toBoolean).getOrElse(false)
                    var logsApplied = false
                    if (wtrLogs) { environment("WTR_BROWSER_LOGS", "1"); logsApplied = true }
                    // Optional live progress (non-static logging): -Pckbuild.wtrLive=true
                    val wtrLive = providers.gradleProperty("ckbuild.wtrLive").map(String::toBoolean).getOrElse(false)
                    var liveApplied = false
                    if (wtrLive) { environment("WTR_LIVE", "1"); liveApplied = true }
                    // Optional fast mode to reduce iterations: -Pckbuild.fast=true
                    val fast = providers.gradleProperty("ckbuild.fast").map(String::toBoolean).getOrElse(false)
                    var fastApplied = false
                    if (fast) { environment("WTR_FAST", "1"); fastApplied = true }
                    // Optional headful/devtools
                    val headful = providers.gradleProperty("ckbuild.wtrHeadful").map(String::toBoolean).getOrElse(false)
                    if (headful) environment("HEADFUL", "1")
                    val devtools = providers.gradleProperty("ckbuild.wtrDevtools").map(String::toBoolean).getOrElse(false)
                    if (devtools) environment("WTR_DEVTOOLS", "1")
                    // Optional concurrency via -Pckbuild.wtrConcurrency=N
                    var concApplied = false
                    providers.gradleProperty("ckbuild.wtrConcurrency").orNull?.let { conc ->
                        if (conc.isNotBlank()) { environment("WTR_CONCURRENCY", conc); concApplied = true }
                    }
                    // Apply environment-based defaults when not explicitly set
                    if (!isCi && !logsApplied) environment("WTR_BROWSER_LOGS", "1")
                    if (!isCi && !liveApplied) environment("WTR_LIVE", "1")
                    if (!isCi && !fastApplied) environment("WTR_FAST", "1")
                    if (!concApplied && !isCi) environment("WTR_CONCURRENCY", "4")

                    // Optional concurrency via -Pckbuild.wtrConcurrency=N
                    providers.gradleProperty("ckbuild.wtrConcurrency").orNull?.let { conc ->
                        if (conc.isNotBlank()) environment("WTR_CONCURRENCY", conc)
                    }

                    // Stream sub-process output to Gradle console
                    standardOutput = System.out
                    errorOutput = System.err
                }
            }
        }
        // not used/supported by wasm
        if (platformType == KotlinPlatformType.js) whenNodejsConfigured {
            testTask {
                useMocha {
                    timeout = "6000s"
                }
            }
        }
    }

    // setup tests running in RELEASE mode
    targets.withType<KotlinNativeTarget>().configureEach {
        binaries.test(listOf(NativeBuildType.RELEASE))
    }
    targets.withType<KotlinNativeTargetWithTests<*>>().configureEach {
        testRuns.create("releaseTest") {
            setExecutionSourceFrom(binaries.getTest(NativeBuildType.RELEASE))
        }
    }
}

// for CI mainly

registerTestAggregationTask(
    name = "wasmTest",
    taskDependencies = { tasks.withType<KotlinJsTest>().matching { it.compilation.platformType == KotlinPlatformType.wasm } },
    targetFilter = { it.platformType == KotlinPlatformType.wasm }
)

registerTestAggregationTask(
    name = "jvmAllTest",
    taskDependencies = { tasks.withType<KotlinJvmTest>() },
    targetFilter = { it.platformType == KotlinPlatformType.jvm }
) {
    // kover is only supported for JVM tests
    finalizedBy("koverVerify")
}

registerTestAggregationTask(
    name = "nativeTest",
    taskDependencies = { tasks.withType<KotlinNativeTest>().matching { it.enabled } },
    targetFilter = { it.platformType == KotlinPlatformType.native }
)

listOf("ios", "watchos", "tvos", "macos").forEach { targetGroup ->
    registerTestAggregationTask(
        name = "${targetGroup}Test",
        taskDependencies = {
            tasks.withType<KotlinNativeTest>().matching {
                it.enabled && it.name.startsWith(targetGroup, ignoreCase = true)
            }
        },
        targetFilter = {
            it.platformType == KotlinPlatformType.native && it.name.startsWith(targetGroup, ignoreCase = true)
        }
    )
}

if (providers.gradleProperty("ckbuild.skipTestTasks").map(String::toBoolean).getOrElse(false)) {
    tasks.matching { it is AbstractTestTask || it is AndroidTestTask || it.name == "koverVerify" }.configureEach { onlyIf { false } }
}
