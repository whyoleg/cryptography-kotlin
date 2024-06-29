/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import org.jetbrains.kotlin.gradle.*
import org.jetbrains.kotlin.gradle.plugin.*

plugins {
    id("ckbuild.multiplatform-base")
    id("com.android.library")
}

android {
    namespace = "${project.group}.${project.name.replace("-", ".")}"
    compileSdk = 34
    defaultConfig {
        minSdk = 21
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    // setup for local dev, on CI same targets are tested but with different approach
    @Suppress("UnstableApiUsage")
    testOptions {
        managedDevices {
            localDevices {
                // minimal supported API
                create("androidApi21") {
                    device = "Pixel 2"
                    apiLevel = 21
                    systemImageSource = "aosp"
                }
                // first API with full JDK 8 support
                create("androidApi27") {
                    device = "Pixel 2"
                    apiLevel = 27
                    systemImageSource = "aosp"
                }
                // latest available for tests API
                create("androidApi33") {
                    device = "Pixel 2"
                    apiLevel = 33
                    systemImageSource = "aosp"
                }
                // atd image is fast
                create("androidFast") {
                    device = "Pixel 2"
                    apiLevel = 33
                    systemImageSource = "aosp-atd"
                }
            }
        }
    }
}

@OptIn(ExperimentalKotlinGradlePluginApi::class)
kotlin {
    jvmToolchain(8)
    androidTarget {
        instrumentedTestVariant.sourceSetTree.set(KotlinSourceSetTree.test)
        unitTestVariant.sourceSetTree.set(KotlinSourceSetTree.unitTest)
    }

    sourceSets {
        invokeWhenCreated("androidInstrumentedTest") {
            dependencies {
                implementation(versionCatalogs.named("libs").findLibrary("androidx-test").get())
            }
        }
    }
}
