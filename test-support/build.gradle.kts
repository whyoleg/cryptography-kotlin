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
                implementation(projects.cryptographyWebcrypto)
            }
        }
        jvmMain {
            dependencies {
                implementation(projects.cryptographyJdk)
            }
        }

        appleMain {
            dependencies {
                implementation(projects.cryptographyApple)
                implementation(projects.cryptographyOpenssl3Prebuilt)
            }
        }

        linuxMain {
            dependencies {
                implementation(projects.cryptographyOpenssl3Prebuilt)
            }
        }

        mingwMain {
            dependencies {
                implementation(projects.cryptographyOpenssl3Prebuilt)
            }
        }
    }
}
