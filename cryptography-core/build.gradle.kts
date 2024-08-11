/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*

plugins {
    id("ckbuild.multiplatform-library")
    id("ckbuild.multiplatform-sweetspi")
}

description = "cryptography-kotlin core API"

kotlin {
    jvmTarget()
    jsTarget()
    nativeTargets()
    wasmTargets()

    sourceSets.commonMain.dependencies {
        api(projects.cryptographyBigint)
        api(projects.cryptographyRandom)
        api(libs.kotlinx.io.core)
    }
}
