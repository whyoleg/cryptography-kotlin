/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*

plugins {
    id("ckbuild.multiplatform-library")
}

description = "cryptography-kotlin API"

kotlin {
    jvmTarget()
    jsTarget()
    nativeTargets()
    wasmTargets()

    sourceSets.commonMain.dependencies {
        api(projects.cryptographyBigint)
        api(libs.kotlinx.io.core)
        api(projects.cryptographyRandom)
    }
}
