/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import org.gradle.kotlin.dsl.*
import org.jetbrains.kotlin.gradle.*
import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.gradle.targets.js.ir.*
import org.jetbrains.kotlin.gradle.targets.jvm.*
import org.jetbrains.kotlin.gradle.targets.jvm.tasks.*
import org.jetbrains.kotlin.gradle.targets.native.tasks.*
import org.jetbrains.kotlin.gradle.tasks.*

plugins {
    kotlin("multiplatform")
    id("org.jetbrains.kotlinx.kover")
}

@OptIn(ExperimentalKotlinGradlePluginApi::class)
kotlin {
    compilerOptions {
        allWarningsAsErrors.set(true)
        progressiveMode.set(true)
        freeCompilerArgs.add("-Xrender-internal-diagnostic-names")
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
        compilations.configureEach {
            compilerOptions.configure {
                freeCompilerArgs.add("-Xjvm-default=all")
            }
        }
    }

    // revisit JS block after WASM support
    targets.withType<KotlinJsIrTarget>().configureEach {
        whenBrowserConfigured {
            testTask {
                useKarma {
                    useConfigDirectory(rootDir.resolve("gradle/js/karma"))
                    useChromeHeadless()
                }
            }
        }
        whenNodejsConfigured {
            testTask {
                useMocha {
                    timeout = "1800s"
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

tasks.register("jvmAllTest") {
    group = "verification"
    dependsOn(tasks.withType<KotlinJvmTest>())
}

tasks.register("nativeTest") {
    group = "verification"
    dependsOn(tasks.withType<KotlinNativeTest>().matching { it.enabled })
}

listOf("ios", "watchos", "tvos", "macos").forEach { targetGroup ->
    tasks.register("${targetGroup}Test") {
        group = "verification"
        dependsOn(tasks.withType<KotlinNativeTest>().matching {
            it.enabled && it.name.startsWith(targetGroup, ignoreCase = true)
        })
    }
}

// on build, link even those binaries, which it's not possible to run
tasks.build {
    dependsOn(tasks.withType<KotlinNativeLink>())
}

