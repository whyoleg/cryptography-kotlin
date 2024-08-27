/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import ckbuild.tests.*
import com.android.build.gradle.internal.tasks.*
import org.jetbrains.kotlin.gradle.*
import org.jetbrains.kotlin.gradle.plugin.*
import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.gradle.targets.js.ir.*
import org.jetbrains.kotlin.gradle.targets.js.testing.*
import org.jetbrains.kotlin.gradle.targets.jvm.*
import org.jetbrains.kotlin.gradle.targets.jvm.tasks.*
import org.jetbrains.kotlin.gradle.targets.native.tasks.*
import org.jetbrains.kotlin.gradle.tasks.*

plugins {
    kotlin("multiplatform")
    id("org.jetbrains.kotlinx.kover")
}

// true by default
val warningsAsErrors = providers.gradleProperty("ckbuild.warningsAsErrors").orNull?.toBoolean() ?: true

@OptIn(ExperimentalKotlinGradlePluginApi::class)
kotlin {
    compilerOptions {
        allWarningsAsErrors.set(warningsAsErrors)
        progressiveMode.set(true)
        freeCompilerArgs.add("-Xrender-internal-diagnostic-names")
        optIn.addAll(OptIns.ExperimentalSubclassOptIn)
    }

    // for some reason just applying `kotlin-test` doesn't work for JVM - revisit after Kotlin 2.0
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

    targets.withType<KotlinJvmTarget>().configureEach {
        compilerOptions {
            freeCompilerArgs.add("-Xjvm-default=all")
        }
    }

    // revisit JS block after WASM support
    targets.withType<KotlinJsIrTarget>().configureEach {
        whenBrowserConfigured {
            testTask {
                useKarma {
                    useConfigDirectory(rootDir.resolve("karma.config.d"))
                    useChromeHeadless()
                }
            }
        }
        // not used/supported by wasm
        if (platformType == KotlinPlatformType.js) whenNodejsConfigured {
            testTask {
                useMocha {
                    timeout = "600s"
                }
            }
        }
    }

    //setup tests running in RELEASE mode
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
)

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

tasks.register("linkAll") {
    dependsOn(tasks.withType<KotlinNativeLink>())
}

if (providers.gradleProperty("ckbuild.skipTestTasks").map(String::toBoolean).getOrElse(false)) {
    tasks.matching { it is AbstractTestTask || it is AndroidTestTask }.configureEach { onlyIf { false } }
}

if (providers.gradleProperty("ckbuild.skipLinkTasks").map(String::toBoolean).getOrElse(false)) {
    tasks.withType<KotlinNativeLink>().configureEach { onlyIf { false } }
}
