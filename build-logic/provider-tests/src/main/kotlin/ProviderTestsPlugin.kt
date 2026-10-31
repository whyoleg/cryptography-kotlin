/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package ckbuild.providertests

import ckbuild.teststorage.*
import com.android.build.gradle.internal.tasks.*
import org.gradle.api.*
import org.gradle.api.tasks.testing.*
import org.gradle.kotlin.dsl.*
import org.jetbrains.kotlin.gradle.*
import org.jetbrains.kotlin.gradle.plugin.*
import org.jetbrains.kotlin.gradle.plugin.mpp.external.*
import org.jetbrains.kotlin.gradle.targets.js.testing.*
import org.jetbrains.kotlin.gradle.targets.jvm.tasks.*
import org.jetbrains.kotlin.gradle.targets.native.tasks.*

// tests of a provider: generated test classes for the provider, test storage and aggregation tasks for CI
abstract class ProviderTestsPlugin : Plugin<Project> {
    override fun apply(target: Project): Unit = with(target) {
        pluginManager.apply(TestStoragePlugin::class)

        // provider tests are run separately on CI, see `run-tests-compatibility.yml`
        val skipProviderTestTasks = providers.gradleProperty("ckbuild.skipProviderTestTasks").map(String::toBoolean).orElse(false)
        tasks.matching { it is AbstractTestTask || it is AndroidTestTask || it.name == "koverVerify" }.configureEach {
            onlyIf { !skipProviderTestTasks.get() }
        }

        plugins.withId("org.jetbrains.kotlin.multiplatform") {
            configureProviderTestsExtension()
            applyProviderTestFilters()
            registerProviderTestAggregationTasks()
        }
    }
}

// for CI mainly
@OptIn(ExternalKotlinTargetApi::class)
private fun Project.registerProviderTestAggregationTasks() {
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
}
