plugins {
    id("buildx-multiplatform")
}

kotlin {
    jvm()

    sourceSets {
        val jvmMain by getting {
            dependencies {
                implementation(libs.ktor.server.core)
                implementation(libs.ktor.server.netty)
                implementation(libs.ktor.server.calllogging)
                implementation(libs.ktor.server.cors)

                implementation(libs.logback.classic)
            }
        }
    }
}
