/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*

plugins {
    id("ckbuild.multiplatform-library")
}

description = "cryptography-kotlin primitives-core"

kotlin {
    allTargets()

    sourceSets.commonMain.dependencies {
        api(projects.cryptographyPrimitives)
    }
}
