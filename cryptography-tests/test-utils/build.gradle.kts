/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    id("buildx-multiplatform")
    id("buildx-target-all")
}

kotlin {
    sourceSets {
        all {
            languageSettings.optInForTests()
        }
        commonMain {
            dependencies {
                api(libs.kotlinx.coroutines.test)
                api(projects.cryptographyCore)
            }
        }
        jsMain {
            dependencies {
                implementation(projects.cryptographyProviders.cryptographyWebcrypto)
            }
        }
        jvmMain {
            dependencies {
                implementation(projects.cryptographyProviders.cryptographyJdk)
            }
        }

        darwinMain {
            dependencies {
                implementation(projects.cryptographyProviders.cryptographyApple)
                implementation(projects.cryptographyProviders.cryptographyOpenssl3.cryptographyOpenssl3Prebuilt)
            }
        }

        linuxMain {
            dependencies {
                implementation(projects.cryptographyProviders.cryptographyOpenssl3.cryptographyOpenssl3Prebuilt)
            }
        }

        mingwMain {
            dependencies {
                implementation(projects.cryptographyProviders.cryptographyOpenssl3.cryptographyOpenssl3Prebuilt)
            }
        }
    }
}
