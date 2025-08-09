/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

@file:Suppress("UnstableApiUsage")

package ckbuild

import com.android.build.api.dsl.*
import org.gradle.jvm.toolchain.*
import org.gradle.kotlin.dsl.*
import org.jetbrains.kotlin.gradle.*
import org.jetbrains.kotlin.gradle.dsl.*

fun KotlinMultiplatformExtension.allTargets(
    supportsWasmWasi: Boolean = true,
) {
    jvmTarget()
    webTargets()
    nativeTargets()
    if (supportsWasmWasi) wasmWasiTarget()
}

fun KotlinMultiplatformExtension.allBenchmarkTargets() {
    jvmTarget(jdkAdditionalTestVersions = emptySet())
    desktopTargets()
    webTargets(supportsBrowser = false)
}

fun KotlinMultiplatformExtension.appleTargets(
    // not supported by Swift anymore -> not supported by CryptoKit
    supportsWatchosArm32: Boolean = true,
) {
    macosX64()
    macosArm64()

    iosArm64()
    iosX64()
    iosSimulatorArm64()

    watchosX64()
    if (supportsWatchosArm32) watchosArm32()
    watchosArm64()
    watchosSimulatorArm64()
    watchosDeviceArm64()

    tvosX64()
    tvosArm64()
    tvosSimulatorArm64()
}

fun KotlinMultiplatformExtension.desktopTargets() {
    linuxX64()
    linuxArm64()

    mingwX64()

    macosX64()
    macosArm64()
}

fun KotlinMultiplatformExtension.nativeTargets() {
    appleTargets()
    desktopTargets()

    androidNativeX64()
    androidNativeX86()
    androidNativeArm64()
    androidNativeArm32()
}

fun KotlinMultiplatformExtension.jsTarget(
    supportsBrowser: Boolean = true,
) {
    js {
        nodejs()
        if (supportsBrowser) browser()
    }
}

@OptIn(ExperimentalWasmDsl::class)
fun KotlinMultiplatformExtension.wasmJsTarget(
    supportsBrowser: Boolean = true,
) {
    wasmJs {
        nodejs()
        if (supportsBrowser) browser()
    }
}

@OptIn(ExperimentalWasmDsl::class)
fun KotlinMultiplatformExtension.wasmWasiTarget() {
    wasmWasi {
        nodejs()
    }
}

fun KotlinMultiplatformExtension.webTargets(
    supportsBrowser: Boolean = true,
) {
    jsTarget(supportsBrowser = supportsBrowser)
    wasmJsTarget(supportsBrowser = supportsBrowser)
}

fun KotlinMultiplatformExtension.jvmTarget(
    jdkAdditionalTestVersions: Set<Int> = setOf(11, 17, 21),
) {
    jvm {
        val javaToolchains = project.extensions.getByName<JavaToolchainService>("javaToolchains")

        jdkAdditionalTestVersions.forEach { jdkTestVersion ->
            testRuns.create("${jdkTestVersion}Test") {
                executionTask.configure {
                    javaLauncher.set(javaToolchains.launcherFor {
                        languageVersion.set(JavaLanguageVersion.of(jdkTestVersion))
                    })
                }
            }
        }
    }

    //version enforcement using bom works only for jvm
    sourceSets.jvmMain.dependencies {
        api(project.dependencies.platform(project(":cryptography-bom")))
    }
}

fun KotlinMultiplatformExtension.androidLibraryTarget() {
    project.plugins.apply("com.android.kotlin.multiplatform.library")

    androidLibrary {
        namespace = "${project.group}.${project.name.replace("-", ".")}"
        compileSdk = 36
        minSdk = 21

        withDeviceTestBuilder {
            // to make it dependent on `commonTest`
            sourceSetTreeName = "test"
        }.configure {
            instrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        }
    }

    sourceSets.named("androidDeviceTest") {
        dependencies {
            implementation(project.versionCatalogLib("androidx-test"))
        }
    }

    project.tasks.named("check") {
        dependsOn(project.tasks.named("androidConnectedCheck"))
    }
}
