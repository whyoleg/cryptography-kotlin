/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import ckbuild.tests.*
import org.jetbrains.kotlin.gradle.plugin.*
import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.gradle.targets.js.ir.*
import org.jetbrains.kotlin.gradle.targets.js.testing.*
import org.jetbrains.kotlin.gradle.targets.jvm.tasks.*
import org.jetbrains.kotlin.gradle.targets.native.tasks.*
import org.jetbrains.kotlin.gradle.tasks.*

plugins {
    kotlin("multiplatform")
    id("ckbuild.kotlin")
}

// region link tasks

val skipLinkTasks = booleanProperty("ckbuild.skipLinkTasks", defaultValue = false)
val skipReleaseLinkTasks = booleanProperty("ckbuild.skipReleaseLinkTasks", defaultValue = false)

kotlin {
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

tasks.register("linkAll") {
    dependsOn(tasks.withType<KotlinNativeLink>())
}

tasks.withType<KotlinNativeLink>().configureEach {
    val isRelease = binary.buildType == NativeBuildType.RELEASE
    val skipLinkTasks = skipLinkTasks // for CC
    val skipReleaseLinkTasks = skipReleaseLinkTasks // for CC
    onlyIf { !skipLinkTasks.get() }
    if (isRelease) onlyIf { !skipReleaseLinkTasks.get() }
}

// endregion link tasks

// region js config

kotlin {
    targets.withType<KotlinJsIrTarget>().configureEach {
        whenBrowserConfigured {
            testTask {
                useKarma {
                    useConfigDirectory(rootDir.resolve("karma.config.d"))
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

}

// endregion js config

// region shortcut tasks
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

// endregion shortcut tasks
