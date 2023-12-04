/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import org.jetbrains.kotlin.gradle.*

plugins {
    id("ckbuild.multiplatform-base")
    id("ckbuild.multiplatform-android")

    id("org.jetbrains.kotlin.plugin.serialization")
}

@OptIn(ExperimentalKotlinGradlePluginApi::class)
kotlin {
    jvmTarget()
    jsTarget()
    nativeTargets()

    compilerOptions {
        optIn.addAll(
            OptIns.InsecureAlgorithm,
            OptIns.CryptographyProviderApi,
        )
    }

    sourceSets {
        commonMain.dependencies {
            api(projects.cryptographyCore)
            api(libs.kotlinx.coroutines.test)
            api(libs.kotlinx.serialization.json)
        }
        jsMain.dependencies {
            implementation(projects.cryptographyProviderWebcrypto)
        }
        jvmMain.dependencies {
            implementation(projects.cryptographyProviderJdk)
            implementation(libs.bouncycastle.jdk8)
        }
        androidMain.dependencies {
            implementation(projects.cryptographyProviderJdk)
            implementation(libs.bouncycastle.jdk8)
        }
        nativeMain.dependencies {
            implementation(projects.cryptographyProviderOpenssl3Prebuilt)
        }
        appleMain.dependencies {
            implementation(projects.cryptographyProviderApple)
        }
    }
}
