/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import org.jetbrains.kotlin.gradle.*

plugins {
    id("ckbuild.multiplatform-library")
    id("org.jetbrains.kotlin.plugin.serialization")
}

description = "cryptography-kotlin BigInt API"

@OptIn(ExperimentalKotlinGradlePluginApi::class)
kotlin {
    allTargets()

    compilerOptions {
        freeCompilerArgs.add("-Xexpect-actual-classes")
    }

    applyDefaultHierarchyTemplate {
        common {
            group("nonJvm") {
                // js and wasmJs
                group("jsAndWasmJs") {
                    withJs()
                    withWasmJs()
                }
                // all native targets + wasmWasi
                group("nativeAndWasmWasi") {
                    group("native")
                    withWasmWasi()
                }
            }
        }
    }

    sourceSets {
        commonMain.dependencies {
            compileOnly(libs.kotlinx.serialization.core)
        }
        // other targets don't support `compileOnly` dependencies
        named("nonJvmMain").dependencies {
            api(libs.kotlinx.serialization.core)
        }
    }
}
