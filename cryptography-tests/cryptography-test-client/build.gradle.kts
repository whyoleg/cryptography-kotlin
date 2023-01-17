import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.konan.target.*

plugins {
    id("buildx-multiplatform")
    alias(libs.plugins.kotlin.serialization)
}

kotlin {
    allTargets()

    sharedSourceSet("mingw") { (it as? KotlinNativeTarget)?.konanTarget?.family == Family.MINGW }
    sharedSourceSet("linux") { (it as? KotlinNativeTarget)?.konanTarget?.family == Family.LINUX }
    sharedSourceSet("darwin") { (it as? KotlinNativeTarget)?.konanTarget?.family?.isAppleFamily == true }
    sourceSets {
        commonMain {
            dependencies {
                api(libs.ktor.client.core)
            }
        }
        val jvmMain by getting {
            dependencies {
                implementation(libs.ktor.client.okhttp)
            }
        }
        val linuxMain by getting {
            dependencies {
                implementation(libs.ktor.client.cio)
            }
        }
        val darwinMain by getting {
            dependencies {
                implementation(libs.ktor.client.cio)
            }
        }
        val mingwMain by getting {
            dependencies {
                implementation(libs.ktor.client.winhttp)
            }
        }
    }
}
