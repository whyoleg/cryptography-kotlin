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
                implementation(projects.cryptographyProviders.cryptographyOpenssl3.cryptographyOpenssl3Static)
            }
        }

        linuxMain {
            dependencies {
                implementation(projects.cryptographyProviders.cryptographyOpenssl3.cryptographyOpenssl3Static)
            }
        }

        mingwMain {
            dependencies {
                implementation(projects.cryptographyProviders.cryptographyOpenssl3.cryptographyOpenssl3Static)
            }
        }
    }
}
