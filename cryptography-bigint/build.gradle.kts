/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import org.jetbrains.kotlin.gradle.*
import org.jetbrains.kotlin.gradle.plugin.*
import org.jetbrains.kotlin.gradle.targets.js.*
import org.jetbrains.kotlin.gradle.targets.js.ir.*

plugins {
    id("ckbuild.multiplatform-library")
    alias(kotlinLibs.plugins.serialization)
}

description = "cryptography-kotlin BigInt API"

@OptIn(ExperimentalKotlinGradlePluginApi::class)
kotlin {
    jvmTarget()
    jsTarget()
    nativeTargets()
    wasmTargets()

    compilerOptions {
        freeCompilerArgs.add("-Xexpect-actual-classes")
    }

    applyDefaultHierarchyTemplate {
        common {
            // js and wasmJs
            group("jsAndWasmJs") {
                withJs()
                withCompilations { (it.target as? KotlinJsIrTarget)?.wasmTargetType == KotlinWasmTargetType.JS }
            }
            // all native targets + wasmWasi
            group("nativeAndWasmWasi") {
                group("native")
                withCompilations { (it.target as? KotlinJsIrTarget)?.wasmTargetType == KotlinWasmTargetType.WASI }
            }
            group("nonJvm") {
                withCompilations { it.platformType != KotlinPlatformType.jvm }
            }
        }
    }

    sourceSets {
        commonMain.dependencies {
            compileOnly(libs.kotlinx.serialization.core)
        }
        // other targets don't support `compileOnly` dependencies
        named("nonJvmMain").dependencies {
            implementation(libs.kotlinx.serialization.core)
        }
    }
}
