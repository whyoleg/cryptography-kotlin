import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.konan.target.*

plugins {
    id("buildx-multiplatform")
}

kotlin {
    allTargets()

    sharedSourceSet("mingw") { (it as? KotlinNativeTarget)?.konanTarget?.family == Family.MINGW }
    sharedSourceSet("linux") { (it as? KotlinNativeTarget)?.konanTarget?.family == Family.LINUX }
    sharedSourceSet("darwin") { (it as? KotlinNativeTarget)?.konanTarget?.family?.isAppleFamily == true }
    sourceSets {
        commonMain {
            dependencies {
                api(projects.cryptographyCore)
                api(projects.cryptographyTests.cryptographyTestClient)
            }
        }
        commonTest {
            dependencies {
                implementation(libs.kotlinx.coroutines.test)
                implementation(kotlin("test"))
            }
        }

        val jsMain by getting {
            dependencies {
                implementation(projects.cryptographyProviders.cryptographyWebcrypto)
            }
        }
        val darwinMain by getting {
            dependencies {
                implementation(projects.cryptographyProviders.cryptographyApple)
            }
        }
        val jvmMain by getting {
            dependencies {
                implementation(projects.cryptographyProviders.cryptographyJdk)
            }
        }
    }
}
