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
                api(kotlin("test"))
                api(libs.kotlinx.coroutines.test)
                api(projects.cryptographyCore)
            }
        }
        val jsMain by getting {
            dependencies {
                api(kotlin("test-js"))
                implementation(projects.cryptographyWebcrypto)
            }
        }
        val jvmMain by getting {
            dependencies {
                api(kotlin("test-junit"))
                implementation(projects.cryptographyJdk)
            }
        }

        val darwinMain by getting {
            dependencies {
                implementation(projects.cryptographyApple)
            }
        }
    }
}
