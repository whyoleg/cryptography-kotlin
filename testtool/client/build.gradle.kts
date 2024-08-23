/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import org.jetbrains.kotlin.gradle.*
import org.jetbrains.kotlin.gradle.plugin.*
import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.konan.target.*

plugins {
    alias(libs.plugins.kotlin.multiplatform)
}

@OptIn(ExperimentalWasmDsl::class)
kotlin {
    jvmToolchain(8)

    jvm()
    js(IR) {
        nodejs()
        browser()
    }
    wasmJs {
        // No support from KTOR
        nodejs()
        browser()
    }

    iosArm64()
    iosX64()
    iosSimulatorArm64()

    watchosX64()
    watchosArm32()
    watchosArm64()
    watchosSimulatorArm64()

    tvosX64()
    tvosArm64()
    tvosSimulatorArm64()

    macosX64()
    macosArm64()

    linuxX64()
    linuxArm64()
    mingwX64()

    // No support from KTOR
    watchosDeviceArm64()
    androidNativeX64()
    androidNativeX86()
    androidNativeArm64()
    androidNativeArm32()

    val supportsKtor: (KotlinCompilation<*>).() -> Boolean = {
        val konanTarget = (target as? KotlinNativeTarget)?.konanTarget
        when {
            konanTarget == KonanTarget.WATCHOS_DEVICE_ARM64 -> false
            konanTarget?.family == Family.ANDROID           -> false
            platformType == KotlinPlatformType.wasm         -> false
            else                                            -> true
        }
    }

    @OptIn(ExperimentalKotlinGradlePluginApi::class)
    applyDefaultHierarchyTemplate {
        common {
            group("nonJvm") {
                withCompilations { it.platformType != KotlinPlatformType.jvm }
            }
            group("ktor") {
                withCompilations(supportsKtor)
            }
            group("nonKtor") {
                withCompilations { !supportsKtor(it) }
            }
            group("cio") {
                withCompilations {
                    val target = (it.target as? KotlinNativeTarget)?.konanTarget
                    when {
                        target == KonanTarget.WATCHOS_DEVICE_ARM64 -> false
                        target?.family?.isAppleFamily == true      -> true
                        target?.family == Family.LINUX             -> true
                        else                                       -> false
                    }
                }
            }
        }
    }

    sourceSets {
        val commonMain by getting {
            dependencies {
                api(libs.kotlinx.coroutines.core)
            }
        }
        val ktorMain by getting {
            dependencies {
                implementation(libs.ktor.client.core)
            }
        }
        val jvmMain by getting {
            dependencies {
                implementation(libs.ktor.client.okhttp)
            }
        }
        val cioMain by getting {
            dependencies {
                implementation(libs.ktor.client.cio)
            }
        }
        val mingwMain by getting {
            dependencies {
                implementation(libs.ktor.client.winhttp)
            }
        }
    }
}
