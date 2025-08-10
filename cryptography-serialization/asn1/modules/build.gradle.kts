/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*

plugins {
    id("ckbuild.multiplatform-library")
    id("org.jetbrains.kotlin.plugin.serialization")
}

description = "cryptography-kotlin ASN.1 modules"

kotlin {
    allTargets()

    sourceSets {
        commonMain.dependencies {
            api(projects.cryptographySerializationAsn1)
        }
    }
}
