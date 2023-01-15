import org.jetbrains.kotlin.gradle.plugin.*
import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.konan.target.*

plugins {
    id("buildx-multiplatform")
    id("build-parameters")
}

kotlin {
    allTargets()

    sharedSourceSet("native") { it is KotlinNativeTarget }
    sharedSourceSet("mingw") { (it as? KotlinNativeTarget)?.konanTarget?.family == Family.MINGW }
    sharedSourceSet("linux") { (it as? KotlinNativeTarget)?.konanTarget?.family == Family.LINUX }
    sharedSourceSet("darwin") { (it as? KotlinNativeTarget)?.konanTarget?.family?.isAppleFamily == true }
    sourceSets {
        commonTest {
            dependencies {
                implementation(kotlin("test"))
                implementation(libs.kotlinx.coroutines.test)

                implementation(projects.cryptographyTestClient)
                implementation(projects.cryptographyCore)
            }
        }
        val jsTest by getting {
            dependencies {
                implementation(projects.cryptographyWebcrypto)
            }
        }
        val darwinTest by getting {
            dependencies {
                implementation(projects.cryptographyApple)
            }
        }
        val jvmTest by getting {
            dependencies {
                implementation(kotlin("test-junit")) //TODO: why it's not added automatically?
                implementation(projects.cryptographyJdk)
            }
        }
    }

    buildParameters.testsuite.step.orNull?.let { testNamePattern ->
        targets.all {
            if (this is KotlinTargetWithTests<*, *>) testRuns.all {
                filter {
                    includeTestsMatching(testNamePattern.name)
                }
            }
        }
    }
}
