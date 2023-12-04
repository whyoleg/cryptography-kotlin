/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*

plugins {
    id("ckbuild.multiplatform-library")
}

description = "cryptography-kotlin core API"

kotlin {
    jvmTarget()
    jsTarget()
    nativeTargets()

    sourceSets.commonMain.dependencies {
        api(projects.cryptographyRandom)
    }
}
