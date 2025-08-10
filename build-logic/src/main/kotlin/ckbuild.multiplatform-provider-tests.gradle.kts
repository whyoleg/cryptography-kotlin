/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.tests.*
import com.android.build.gradle.internal.tasks.*
import org.jetbrains.kotlin.gradle.*
import org.jetbrains.kotlin.gradle.plugin.*
import org.jetbrains.kotlin.gradle.plugin.mpp.external.*
import org.jetbrains.kotlin.gradle.targets.js.testing.*
import org.jetbrains.kotlin.gradle.targets.jvm.tasks.*
import org.jetbrains.kotlin.gradle.targets.native.tasks.*

plugins {
    id("ckbuild.multiplatform-tests")
    id("testtool.server")
}

kotlin {
    sourceSets.commonTest.dependencies {
        implementation(project(":cryptography-provider-tests"))
    }
}

configureProviderTestsExtension()
applyProviderTestFilters()

// for CI mainly

@OptIn(ExternalKotlinTargetApi::class)
registerTestAggregationTask(
    name = "connectedAndroidProviderTest",
    taskDependencies = { tasks.matching { it is AndroidTestTask && it.name.startsWith("connected", ignoreCase = true) } },
    targetFilter = { it is DecoratedExternalKotlinTarget /* only android for now, so should be safe */ }
)

registerTestAggregationTask(
    name = "wasmProviderTest",
    taskDependencies = { tasks.withType<KotlinJsTest>().matching { it.compilation.platformType == KotlinPlatformType.wasm } },
    targetFilter = { it.platformType == KotlinPlatformType.wasm }
)

registerTestAggregationTask(
    name = "jsProviderTest",
    taskDependencies = { tasks.withType<KotlinJsTest>().matching { it.compilation.platformType == KotlinPlatformType.js } },
    targetFilter = { it.platformType == KotlinPlatformType.js }
)

registerTestAggregationTask(
    name = "jvmAllProviderTest",
    taskDependencies = { tasks.withType<KotlinJvmTest>() },
    targetFilter = { it.platformType == KotlinPlatformType.jvm }
) {
    // kover is only supported for JVM tests
    finalizedBy("koverVerify")
}

// test only on min and max JDK versions
registerTestAggregationTask(
    name = "jvmProviderTest",
    taskDependencies = {
        tasks.withType<KotlinJvmTest>().matching {
            it.javaLauncher.get().metadata.languageVersion.asInt() in setOf(8, 21)
        }
    },
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
