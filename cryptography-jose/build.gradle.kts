/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*

plugins {
    id("ckbuild.multiplatform-library")
    alias(libs.plugins.kotlin.plugin.serialization)
}

description = "cryptography-kotlin JOSE support"

kotlin {
    jvmTarget()
    jsTarget()
    nativeTargets()
    wasmTargets()

    sourceSets.commonMain.dependencies {
        api(projects.cryptographyCore)
        implementation(libs.kotlinx.serialization.json)
    }
    
    sourceSets.commonTest.dependencies {
        implementation(libs.kotlin.test)
    }
}