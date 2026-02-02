/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import org.jetbrains.kotlin.gradle.*

plugins {
    id("ckbuild.multiplatform-library")
    id("org.jetbrains.kotlin.plugin.serialization")
}

description = "cryptography-kotlin BigInt API"

kotlin {
    allTargets()

    compilerOptions {
        freeCompilerArgs.add("-Xexpect-actual-classes")
    }

    @OptIn(ExperimentalKotlinGradlePluginApi::class)
    applyDefaultHierarchyTemplate {
        common {
            group("nonJvm") {
                group("web")
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
