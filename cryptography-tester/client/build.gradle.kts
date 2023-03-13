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
        darwinMain {
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
