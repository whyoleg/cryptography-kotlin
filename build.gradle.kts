/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import org.jetbrains.kotlin.gradle.targets.js.nodejs.*
import org.jetbrains.kotlin.gradle.targets.js.npm.*
import org.jetbrains.kotlin.gradle.targets.wasm.nodejs.*
import org.jetbrains.kotlin.gradle.targets.wasm.npm.*
import org.gradle.language.base.plugins.LifecycleBasePlugin
import org.gradle.api.tasks.Exec
import dev.whyoleg.cryptography.testtool.plugin.TesttoolServerConfiguration
import dev.whyoleg.cryptography.testtool.plugin.TesttoolServerService

plugins {
    alias(libs.plugins.kotlin.dokka)

    alias(libs.plugins.android.kotlin.multiplatform.library) apply false
    alias(libs.plugins.kotlin.multiplatform) apply false
    alias(libs.plugins.kotlin.plugin.serialization) apply false

    id("ckbuild.use-openssl")
}

Projects.validateProjectTags(project)

// ignore package lock
plugins.withType<NodeJsRootPlugin> {
    extensions.configure<NpmExtension> {
        lockFileDirectory.set(layout.buildDirectory.dir("kotlin-js-store/js"))
        packageLockMismatchReport.set(LockFileMismatchReport.NONE)
    }
}
plugins.withType<WasmNodeJsRootPlugin> {
    extensions.configure<WasmNpmExtension> {
        lockFileDirectory.set(layout.buildDirectory.dir("kotlin-js-store/wasm"))
        packageLockMismatchReport.set(LockFileMismatchReport.NONE)
    }
}

dokka {
    setupHomepageLink()
}

dependencies {
    Projects.libraries.forEach {
        dokka(project(":$it"))
    }
}

tasks.dokkaGeneratePublicationHtml {
    outputDirectory.set(file("docs/api"))
}

tasks.register<Copy>("mkdocsCopy") {
    into(rootDir.resolve("docs"))
    from("CHANGELOG.md")
}

tasks.register<Exec>("mkdocsBuild") {
    dependsOn(tasks.dokkaGeneratePublicationHtml)
    dependsOn(tasks.named("mkdocsCopy"))
    commandLine("mkdocs", "build", "--clean", "--strict")
}


// Install Playwright browser once for all runs (Chrome for Testing)
val installBrowsers = tasks.register<Exec>("installBrowsers") {
    group = LifecycleBasePlugin.VERIFICATION_GROUP
    description = "Install Playwright browser (Chrome for Testing)"
    // Install Chrome for Testing with required OS deps (especially useful on CI)
    commandLine("bash", "-lc", "pnpm exec playwright install --with-deps chrome")
}

// Convenience alias for WebCrypto browser tests
tasks.register<Exec>("jsBrowserTest") {
    group = LifecycleBasePlugin.VERIFICATION_GROUP
    description = "Run JS WebCrypto browser tests via a single Web Test Runner (Playwright Chrome)"

    // Ensure all split JS browser test bundles are compiled
    val testModules = listOf(
        ":cryptography-provider-webcrypto-tests-core",
        ":cryptography-provider-webcrypto-tests-aes",
        ":cryptography-provider-webcrypto-tests-mac",
        ":cryptography-provider-webcrypto-tests-ec",
        ":cryptography-provider-webcrypto-tests-rsa",
        ":cryptography-provider-webcrypto-tests-compat",
    )
    testModules.forEach { path ->
        dependsOn(project(path).tasks.matching { it.name == "jsTestTestDevelopmentExecutableCompileSync" })
    }

    // Start Testtool server via BuildService and keep it alive
    val testtoolConfig = TesttoolServerConfiguration(rootProject)
    val wtrServerService = gradle.sharedServices.registerIfAbsent(
        "wtr-testtool-server-service",
        TesttoolServerService::class.java
    ) {
        parameters.instanceId.set(providers.gradleProperty("ckbuild.testtool.instanceId").orElse("wtr"))
        parameters.storage.set(testtoolConfig.serverStorageDir)
    }
    usesService(wtrServerService)
    doFirst { wtrServerService.get() }

    // WTR runs from repository root so glob picks up all split modules' test bundles
    workingDir = rootProject.projectDir

    // Collect globs for split modules
    val filesGlobs = testModules.joinToString(" ") { modulePath ->
        val rel = project(modulePath).projectDir.relativeTo(rootProject.projectDir).path.replace(File.separatorChar, '/')
        "$rel/build/compileSync/js/test/testDevelopmentExecutable/kotlin/*-test.mjs"
    }

    val cmd = listOf(
        "bash", "-lc",
        "set -o pipefail; " +
            "WTR_FILES='$filesGlobs' pnpm exec web-test-runner --config web-test-runner.config.mjs | tee 'build/wtr-webcrypto-all.log'; " +
            "status=${'$'}{PIPESTATUS[0]}; exit ${'$'}status"
    )
    commandLine = cmd

    // Optional flags mapping
    providers.gradleProperty("ckbuild.wtrGrep").orNull?.let { grep ->
        if (grep.isNotBlank()) environment("WTR_GREP", grep)
    }
    if (!System.getenv().containsKey("WTR_GREP")) {
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
    val isCi = System.getenv("CI") != null || System.getenv("GITHUB_ACTIONS") != null
    val logsOn = providers.gradleProperty("ckbuild.wtrLogs").map(String::toBoolean).getOrElse(false)
    var logsApplied = false
    if (logsOn) { environment("WTR_BROWSER_LOGS", "1"); logsApplied = true }
    val liveOn = providers.gradleProperty("ckbuild.wtrLive").map(String::toBoolean).getOrElse(false)
    var liveApplied = false
    if (liveOn) { environment("WTR_LIVE", "1"); liveApplied = true }
    val fastOn = providers.gradleProperty("ckbuild.fast").map(String::toBoolean).getOrElse(false)
    var fastApplied = false
    if (fastOn) { environment("WTR_FAST", "1"); fastApplied = true }
    var concApplied = false
    providers.gradleProperty("ckbuild.wtrConcurrency").orNull?.let { conc ->
        if (conc.isNotBlank()) { environment("WTR_CONCURRENCY", conc); concApplied = true }
    }
    if (!isCi && !logsApplied) environment("WTR_BROWSER_LOGS", "1")
    if (!isCi && !liveApplied) environment("WTR_LIVE", "1")
    if (!isCi && !fastApplied) environment("WTR_FAST", "1")
    if (!concApplied && !isCi) environment("WTR_CONCURRENCY", "4")
    // Optional headful/devtools
    providers.gradleProperty("ckbuild.wtrHeadful").map(String::toBoolean).getOrElse(false).let { on ->
        if (on) environment("HEADFUL", "1")
    }
    providers.gradleProperty("ckbuild.wtrDevtools").map(String::toBoolean).getOrElse(false).let { on ->
        if (on) environment("WTR_DEVTOOLS", "1")
    }

    // Stream WTR output
    standardOutput = System.out
    errorOutput = System.err
    notCompatibleWithConfigurationCache("Exec task streams output and uses a BuildService")
}

fun Project.registerJsBrowserGroupTask(name: String, modulePath: String, descriptionText: String) =
    tasks.register<Exec>(name) {
        group = LifecycleBasePlugin.VERIFICATION_GROUP
        description = descriptionText

        // Ensure bundle compiled
        dependsOn(project(modulePath).tasks.matching { it.name == "jsTestTestDevelopmentExecutableCompileSync" })

        val testtoolConfig = TesttoolServerConfiguration(rootProject)
        val wtrServerService = gradle.sharedServices.registerIfAbsent(
            "wtr-testtool-server-service",
            TesttoolServerService::class.java
        ) {
            parameters.instanceId.set(providers.gradleProperty("ckbuild.testtool.instanceId").orElse("wtr"))
            parameters.storage.set(testtoolConfig.serverStorageDir)
        }
        usesService(wtrServerService)
        doFirst { wtrServerService.get() }

        workingDir = rootProject.projectDir
        val rel = project(modulePath).projectDir.relativeTo(rootProject.projectDir).path.replace(File.separatorChar, '/')
        val filesGlob = "$rel/build/compileSync/js/test/testDevelopmentExecutable/kotlin/*-test.mjs"
        val cmd = listOf(
            "bash", "-lc",
            "set -o pipefail; " +
                "WTR_FILES='$filesGlob' pnpm exec web-test-runner --config web-test-runner.config.mjs | tee 'build/wtr-${name}.log'; " +
                "status=${'$'}{PIPESTATUS[0]}; exit ${'$'}status"
        )
        commandLine = cmd

        // Flags
        providers.gradleProperty("ckbuild.wtrGrep").orNull?.let { grep ->
            if (grep.isNotBlank()) environment("WTR_GREP", grep)
        }
        if (!System.getenv().containsKey("WTR_GREP")) {
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
        providers.gradleProperty("ckbuild.wtrLogs").map(String::toBoolean).getOrElse(false).let { on ->
            if (on) environment("WTR_BROWSER_LOGS", "1")
        }
        providers.gradleProperty("ckbuild.wtrLive").map(String::toBoolean).getOrElse(false).let { on ->
            if (on) environment("WTR_LIVE", "1")
        }
        providers.gradleProperty("ckbuild.fast").map(String::toBoolean).getOrElse(false).let { on ->
            if (on) environment("WTR_FAST", "1")
        }
        providers.gradleProperty("ckbuild.wtrConcurrency").orNull?.let { conc ->
            if (conc.isNotBlank()) environment("WTR_CONCURRENCY", conc)
        }
        // Optional headful/devtools
        providers.gradleProperty("ckbuild.wtrHeadful").map(String::toBoolean).getOrElse(false).let { on ->
            if (on) environment("HEADFUL", "1")
        }
        providers.gradleProperty("ckbuild.wtrDevtools").map(String::toBoolean).getOrElse(false).let { on ->
            if (on) environment("WTR_DEVTOOLS", "1")
        }

        standardOutput = System.out
        errorOutput = System.err
        notCompatibleWithConfigurationCache("Exec task streams output and uses a BuildService")
    }

registerJsBrowserGroupTask(
    name = "jsBrowserTestCore",
    modulePath = ":cryptography-provider-webcrypto-tests-core",
    descriptionText = "Run WebCrypto core browser tests (KDF + digests)"
)
registerJsBrowserGroupTask(
    name = "jsBrowserTestCompat",
    modulePath = ":cryptography-provider-webcrypto-tests-compat",
    descriptionText = "Run WebCrypto Compatibility browser tests"
)
registerJsBrowserGroupTask(
    name = "jsBrowserTestAes",
    modulePath = ":cryptography-provider-webcrypto-tests-aes",
    descriptionText = "Run WebCrypto AES browser tests"
)
registerJsBrowserGroupTask(
    name = "jsBrowserTestMac",
    modulePath = ":cryptography-provider-webcrypto-tests-mac",
    descriptionText = "Run WebCrypto MAC (HMAC) browser tests"
)
registerJsBrowserGroupTask(
    name = "jsBrowserTestEc",
    modulePath = ":cryptography-provider-webcrypto-tests-ec",
    descriptionText = "Run WebCrypto EC (ECDSA/ECDH) browser tests"
)
registerJsBrowserGroupTask(
    name = "jsBrowserTestRsa",
    modulePath = ":cryptography-provider-webcrypto-tests-rsa",
    descriptionText = "Run WebCrypto RSA browser tests"
)

// Aggregate JS tests (Node + WebCrypto browser)
tasks.register("jsAllTest") {
    group = LifecycleBasePlugin.VERIFICATION_GROUP
    description = "Run all JS tests (Node + Web Test Runner)"
    dependsOn("jsNodeTest")
    dependsOn("jsBrowserTest")
}
