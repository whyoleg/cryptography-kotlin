/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    id("buildx-multiplatform")
    id("buildx-target-all")
}

kotlin {
    sourceSets {
        commonMain {
            dependencies {
                implementation(libs.ktor.client.core)
            }
        }
        jvmMain {
            dependencies {
                implementation(libs.ktor.client.okhttp)
            }
        }
        linuxMain {
            dependencies {
                implementation(libs.ktor.client.cio)
            }
        }
        appleMain {
            dependencies {
                implementation(libs.ktor.client.cio)
            }
        }
        mingwMain {
            dependencies {
                implementation(libs.ktor.client.winhttp)
            }
        }
    }
}
