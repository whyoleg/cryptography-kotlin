/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    id("ckbuild.multiplatform")
    id("ckbuild.target-native-all")
}

kotlin {
    sourceSets {
        commonMain {
            dependencies {
                api(kotlin("test"))
                api(projects.cryptographyProviderOpenssl3Api)
            }
        }
    }
}
