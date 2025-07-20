/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import org.jetbrains.kotlin.gradle.*
import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.konan.target.*

plugins {
    id("ckbuild.multiplatform-library")
}

description = "cryptography-kotlin optimal provider"

@OptIn(ExperimentalKotlinGradlePluginApi::class)
kotlin {
    allTargets(
        supportsWasmWasi = false
    )

    applyDefaultHierarchyTemplate {
        common {
            group("web") {
                withWasmJs()
                withJs()
            }
            group("native") {
                group("nonApple") {
                    group("mingw")
                    group("linux")
                    group("androidNative")
                }
                group("apple") {
                    group("cryptokitSupported") {
                        withApple()
                        excludeCompilations {
                            (it.target as? KotlinNativeTarget)?.konanTarget == KonanTarget.WATCHOS_ARM32
                        }
                    }
                }
            }
        }
    }

    sourceSets {
        commonMain.dependencies {
            api(projects.cryptographyCore)
        }
        jvmMain.dependencies {
            implementation(projects.cryptographyProviderJdk)
        }
        named("webMain").dependencies {
            implementation(projects.cryptographyProviderWebcrypto)
        }
        appleMain.dependencies {
            implementation(projects.cryptographyProviderApple)
        }
        named("cryptokitSupportedMain").dependencies {
            implementation(projects.cryptographyProviderCryptokit)
        }
        named("nonAppleMain").dependencies {
            implementation(projects.cryptographyProviderOpenssl3Prebuilt)
        }
    }
}
