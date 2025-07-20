/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*

plugins {
    id("ckbuild.multiplatform-library")
    alias(libs.plugins.kotlin.plugin.serialization)
}

description = "cryptography-kotlin ASN.1 (DER) API"

kotlin {
    allTargets()

    sourceSets {
        commonMain.dependencies {
            api(projects.cryptographyBigint)
            api(libs.kotlinx.serialization.core)
        }
    }
}
