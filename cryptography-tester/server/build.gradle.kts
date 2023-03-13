plugins {
    id("buildx-multiplatform")
    id("buildx-target-jvm")
}

kotlin {
    sourceSets {
        jvmMain {
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
