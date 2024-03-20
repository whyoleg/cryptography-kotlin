/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import org.jetbrains.kotlin.gradle.plugin.mpp.*

plugins {
    kotlin("multiplatform") version "2.0.0-Beta5"
}

kotlin {
    val javaOsName = System.getProperty("os.name")
    val javaOsArch = System.getProperty("os.arch")
    when {
        javaOsName.contains("mac", ignoreCase = true)     -> when (javaOsArch) {
            "x86_64", "amd64"  -> macosX64("native")
            "arm64", "aarch64" -> macosArm64("native")
            else               -> error("Unknown os.arch: $javaOsArch")
        }
        javaOsName.contains("linux", ignoreCase = true)   -> linuxX64("native")
        javaOsName.contains("windows", ignoreCase = true) -> mingwX64("native")
        else                                              -> error("Unknown os.name: $javaOsName")
    }

    sourceSets {
        nativeMain.dependencies {
            implementation(cryptographyLibs.core)
            implementation(cryptographyLibs.provider.openssl3.shared)
        }

        nativeTest.dependencies {
            implementation(kotlin("test"))
            implementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.0")
        }
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
