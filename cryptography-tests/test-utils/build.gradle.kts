plugins {
    id("buildx-multiplatform")
}

kotlin {
    allTargets()
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
        val jsMain by getting {
            dependencies {
                implementation(projects.cryptographyProviders.cryptographyWebcrypto)
            }
        }
        val jvmMain by getting {
            dependencies {
                implementation(projects.cryptographyProviders.cryptographyJdk)
            }
        }

        val darwinMain by getting {
            dependencies {
                implementation(projects.cryptographyProviders.cryptographyApple)
                implementation(projects.cryptographyProviders.cryptographyOpenssl3.cryptographyOpenssl3Static)
            }
        }

        val linuxMain by getting {
            dependencies {
                implementation(projects.cryptographyProviders.cryptographyOpenssl3.cryptographyOpenssl3Static)
            }
        }

        val mingwMain by getting {
            dependencies {
                implementation(projects.cryptographyProviders.cryptographyOpenssl3.cryptographyOpenssl3Static)
            }
        }
    }
}
