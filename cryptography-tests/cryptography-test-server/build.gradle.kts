plugins {
    id("buildx-multiplatform")
    alias(libs.plugins.kotlin.serialization)
}

kotlin {
    jvm()

    sourceSets {
        val jvmMain by getting {
            dependencies {
                implementation(projects.cryptographyTests.cryptographyTestApi)

                implementation(libs.ktor.server.core)
                implementation(libs.ktor.server.netty)
                implementation(libs.ktor.server.websockets)
                implementation(libs.ktor.server.contentnegotiation)
                implementation(libs.ktor.server.calllogging)

                implementation(libs.ktor.serialization.kotlinx.protobuf)
                implementation(libs.kotlinx.serialization.protobuf)
                implementation("ch.qos.logback:logback-classic:1.2.11")
            }
        }
    }
}
