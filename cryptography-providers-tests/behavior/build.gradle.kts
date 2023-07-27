/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    id("buildx-multiplatform")
    id("buildx-target-all")
    id("buildx-target-android")
}

kotlin {
    sourceSets {
        commonTest {
            dependencies {
                implementation(projects.cryptographyProvidersTestsSupport)
            }
        }
    }
}
