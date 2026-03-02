/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*

plugins {
    id("ckbuild.multiplatform-library")
}

description = "cryptography-kotlin base provider"

kotlin {
    allTargets()

    sourceSets.commonMain.dependencies {
        api(projects.cryptographyCore)
        api(projects.cryptographySerializationPem)
        api(projects.cryptographySerializationAsn1)
        api(projects.cryptographySerializationAsn1Modules)

        // for JWK support
        implementation(libs.kotlinx.serialization.json)
    }
}
