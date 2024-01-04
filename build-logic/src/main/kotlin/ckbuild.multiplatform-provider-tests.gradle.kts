/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.tests.*
import com.android.build.gradle.internal.tasks.*
import org.jetbrains.kotlin.gradle.plugin.*
import org.jetbrains.kotlin.gradle.targets.js.testing.*
import org.jetbrains.kotlin.gradle.targets.jvm.tasks.*
import org.jetbrains.kotlin.gradle.targets.native.tasks.*

plugins {
    kotlin("multiplatform")
    id("testtool.server")
}

kotlin {
    sourceSets.commonTest.dependencies {
        implementation(project(":cryptography-providers-tests"))
    }
}

configureProviderTestsExtension()
applyProviderTestFilters()

// for CI mainly

registerTestAggregationTask(
    name = "connectedAndroidProviderTest",
    taskDependencies = { tasks.matching { it is AndroidTestTask && it.name.startsWith("connected", ignoreCase = true) } },
    targetFilter = { it.platformType == KotlinPlatformType.androidJvm }
)

registerTestAggregationTask(
    name = "jsProviderTest",
    taskDependencies = { tasks.withType<KotlinJsTest>() },
    targetFilter = { it.platformType == KotlinPlatformType.js }
)

registerTestAggregationTask(
    name = "jvmAllProviderTest",
    taskDependencies = { tasks.withType<KotlinJvmTest>() },
    targetFilter = { it.platformType == KotlinPlatformType.jvm }
)

registerTestAggregationTask(
    name = "nativeProviderTest",
    taskDependencies = { tasks.withType<KotlinNativeTest>().matching { it.enabled } },
    targetFilter = { it.platformType == KotlinPlatformType.native }
)

listOf("ios", "watchos", "tvos", "macos").forEach { targetGroup ->
    registerTestAggregationTask(
        name = "${targetGroup}ProviderTest",
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
