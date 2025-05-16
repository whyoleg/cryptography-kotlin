/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import org.jetbrains.kotlin.gradle.*

plugins {
    kotlin("multiplatform") version "2.0.20"
}

kotlin {
    jvm()
    js {
        nodejs()
        browser()
    }

    @OptIn(ExperimentalWasmDsl::class)
    wasmJs {
        nodejs()
        browser()
    }

    macosX64()
    macosArm64()

    iosArm64()
    iosX64()
    iosSimulatorArm64()

    watchosX64()
    watchosArm32()
    watchosArm64()
    watchosSimulatorArm64()
    watchosDeviceArm64()

    tvosX64()
    tvosArm64()
    tvosSimulatorArm64()

    linuxX64()
    linuxArm64()

    mingwX64()

    androidNativeX64()
    androidNativeX86()
    androidNativeArm64()
    androidNativeArm32()

    sourceSets {
        commonMain.dependencies {
            implementation(cryptographyLibs.core)
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")
        }
        jsMain.dependencies {
            implementation(cryptographyLibs.provider.webcrypto)
        }
        wasmJsMain.dependencies {
            implementation(cryptographyLibs.provider.webcrypto)
        }
        jvmMain.dependencies {
            implementation(cryptographyLibs.provider.jdk)
        }
        nativeMain.dependencies {
            implementation(cryptographyLibs.provider.openssl3.prebuilt)
        }
    }
}
