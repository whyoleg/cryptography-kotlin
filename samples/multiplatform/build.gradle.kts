/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.gradle.targets.js.dsl.*
import org.jetbrains.kotlin.gradle.targets.js.nodejs.*
import org.jetbrains.kotlin.gradle.targets.js.npm.*
import org.jetbrains.kotlin.gradle.targets.js.npm.tasks.*
import org.jetbrains.kotlin.gradle.tasks.*

plugins {
    kotlin("multiplatform") version "2.0.0-Beta5"
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

    linuxX64()
    linuxArm64()

    mingwX64()

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

    androidNativeX64()
    androidNativeX86()
    androidNativeArm64()
    androidNativeArm32()

    sourceSets {
        commonMain.dependencies {
            implementation(cryptographyLibs.core)
        }
        jsMain.dependencies {
            implementation(cryptographyLibs.provider.webcrypto)
        }
        named("wasmJsMain").dependencies {
            implementation(cryptographyLibs.provider.webcrypto)
        }
        jvmMain.dependencies {
            implementation(cryptographyLibs.provider.jdk)
        }
        nativeMain.dependencies {
            implementation(cryptographyLibs.provider.openssl3.prebuilt)
        }

        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.0")
        }
    }
}

plugins.withType<NodeJsRootPlugin> {
    // ignore package lock
    extensions.configure<NpmExtension> {
        lockFileDirectory.set(layout.buildDirectory.dir("kotlin-js-store"))
        packageLockMismatchReport.set(LockFileMismatchReport.NONE)
    }

    // node version with wasm support
    extensions.configure<NodeJsRootExtension> {
        version = "21.0.0-v8-canary202310177990572111"
        downloadBaseUrl = "https://nodejs.org/download/v8-canary"
    }

    // because of custom nodejs version
    tasks.withType<KotlinNpmInstallTask>().configureEach {
        args.add("--ignore-engines")
    }
}

// additional configuration for testing of sample
kotlin {
    targets.withType<KotlinNativeTarget>().configureEach {
        binaries.test(listOf(NativeBuildType.RELEASE))
    }
    targets.withType<KotlinNativeTargetWithTests<*>>().configureEach {
        testRuns.create("releaseTest") {
            setExecutionSourceFrom(binaries.getTest(NativeBuildType.RELEASE))
        }
    }
}

tasks.build {
    dependsOn(tasks.withType<KotlinNativeLink>())
}
