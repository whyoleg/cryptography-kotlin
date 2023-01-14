import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.konan.target.*

plugins {
    id("buildx-multiplatform")
}

kotlin {
    allTargets()

    sharedSourceSet("native") { it is KotlinNativeTarget }
    sharedSourceSet("mingw") { (it as? KotlinNativeTarget)?.konanTarget?.family == Family.MINGW }
    sharedSourceSet("linux") { (it as? KotlinNativeTarget)?.konanTarget?.family == Family.LINUX }
    sharedSourceSet("darwin") { (it as? KotlinNativeTarget)?.konanTarget?.family?.isAppleFamily == true }
    sourceSets {
        commonMain {
            dependencies {
                api(kotlin("test"))
                api(libs.kotlinx.coroutines.test)
                api(projects.cryptographyTestClient)

                api(projects.cryptographyCore)
            }
        }
        val jsMain by getting {
            dependencies {
                api(kotlin("test-js"))

                api(projects.cryptographyWebcrypto)
            }
        }
        val darwinMain by getting {
            dependencies {
                api(projects.cryptographyApple)
            }
        }
        val jvmMain by getting {
            dependencies {
                api(kotlin("test-junit"))

                api(projects.cryptographyJdk)
            }
        }
    }
}
