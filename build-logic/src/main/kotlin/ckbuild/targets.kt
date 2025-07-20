/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package ckbuild

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

fun KotlinMultiplatformExtension.jsTarget() {
    js {
        nodejs()
        browser()
    }
}

@OptIn(ExperimentalWasmDsl::class)
fun KotlinMultiplatformExtension.wasmJsTarget() {
    wasmJs {
        nodejs()
        browser()
    }
}

@OptIn(ExperimentalWasmDsl::class)
fun KotlinMultiplatformExtension.wasmWasiTarget() {
    wasmWasi {
        nodejs()
    }
}

fun KotlinMultiplatformExtension.webTargets() {
    jsTarget()
    wasmJsTarget()
}

fun KotlinMultiplatformExtension.jvmTarget(
    jdkVersion: Int = 8,
    jdkAdditionalTestVersions: Set<Int> = setOf(11, 17, 21),
) {
    jvmToolchain(jdkVersion)

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
