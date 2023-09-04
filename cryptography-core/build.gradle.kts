/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    id("ckbuild.multiplatform-library")
    id("ckbuild.target-all")
}

description = "cryptography-kotlin core API"

kotlin {
    sourceSets {
        commonMain {
            dependencies {
                api(projects.cryptographyRandom)
            }
        }
    }
}
