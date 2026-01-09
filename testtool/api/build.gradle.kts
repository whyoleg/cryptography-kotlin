/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import org.jetbrains.kotlin.gradle.*
import org.jetbrains.kotlin.gradle.dsl.*

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.kotlin.plugin.serialization)
}

@OptIn(ExperimentalWasmDsl::class)
kotlin {
    jvm {
        compilerOptions {
            freeCompilerArgs.add("-Xjdk-release=8")
            jvmTarget = JvmTarget.JVM_1_8
        }
    }
    js(IR) {
        nodejs()
        browser()
    }
    wasmJs {
        nodejs()
        browser()
    }

    iosArm64()
    @Suppress("DEPRECATION") iosX64()
    iosSimulatorArm64()

    @Suppress("DEPRECATION") watchosX64()
    watchosArm32()
    watchosArm64()
    watchosDeviceArm64()
    watchosSimulatorArm64()

    @Suppress("DEPRECATION") tvosX64()
    tvosArm64()
    tvosSimulatorArm64()

    @Suppress("DEPRECATION") macosX64()
    macosArm64()

    linuxX64()
    linuxArm64()
    mingwX64()

    androidNativeX64()
    androidNativeX86()
    androidNativeArm64()
    androidNativeArm32()

    sourceSets {
        commonMain.dependencies {
            api(libs.kotlinx.coroutines.core)
            api(libs.kotlinx.serialization.cbor)
        }
    }
}
