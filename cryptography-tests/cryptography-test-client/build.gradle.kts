plugins {
    id("buildx-multiplatform")
    alias(libs.plugins.kotlin.serialization)
}

kotlin {
    jvm()
    js {
        nodejs()
        browser()
    }

    sourceSets {
        commonMain {
            dependencies {
                implementation(projects.cryptographyTests.cryptographyTestApi)

                implementation(libs.ktor.client.core)
                implementation(libs.ktor.client.websockets)
                implementation(libs.ktor.client.contentnegotiation)

                implementation(libs.ktor.serialization.kotlinx.protobuf)
                implementation(libs.kotlinx.serialization.protobuf)
            }
        }
        val jvmMain by getting {
            dependencies {
                implementation(libs.ktor.client.okhttp)
            }
        }
    }
}
