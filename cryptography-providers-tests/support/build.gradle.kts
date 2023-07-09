/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    id("buildx-multiplatform-test")
    id("buildx-target-all")
}

kotlin {
    sourceSets {
        commonMain {
            dependencies {
                api(libs.kotlinx.coroutines.test)
                api(projects.cryptographyCore)
            }
        }
        jsMain {
            dependencies {
                implementation(projects.cryptographyProviderWebcrypto)
            }
        }
        jvmMain {
            dependencies {
                implementation(projects.cryptographyProviderJdk)
                implementation(libs.bouncycastle.jdk8)
            }
        }

        appleMain {
            dependencies {
                implementation(projects.cryptographyProviderApple)
                implementation(projects.cryptographyProviderOpenssl3Prebuilt)
            }
        }

        linuxMain {
            dependencies {
                implementation(projects.cryptographyProviderOpenssl3Prebuilt)
            }
        }

        mingwMain {
            dependencies {
                implementation(projects.cryptographyProviderOpenssl3Prebuilt)
            }
        }
    }
}