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
