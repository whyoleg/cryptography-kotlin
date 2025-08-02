/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*

plugins {
    id("ckbuild.multiplatform-library")
    alias(libs.plugins.kotlin.plugin.serialization)
}

description = "cryptography-kotlin COSE API"

kotlin {
    jvmTarget()
    jsTarget()
    nativeTargets()
    wasmTargets()

    sourceSets {
        commonMain.dependencies {
            api(libs.kotlinx.serialization.cbor)
        }
    }
}
