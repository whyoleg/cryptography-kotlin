import org.jetbrains.kotlin.gradle.dsl.*
import org.jetbrains.kotlin.gradle.plugin.*

fun KotlinMultiplatformExtension.jsTargets() {
    js {
        nodejs {
            testTask {
                useMocha {
                    timeout = "600s"
                }
            }
        }
        browser {
            testTask {
                useKarma {
                    useConfigDirectory(project.rootDir.resolve("gradle/js/karma"))
                    useChromeHeadless()
                    //useSafari()
                }
            }
        }
    }
}

private fun KotlinMultiplatformExtension.nonAppleTargets() {
    linuxX64()
    mingwX64()
}

private fun KotlinMultiplatformExtension.appleDesktopTargets() {
    macosX64()
    macosArm64()
}

private fun KotlinMultiplatformExtension.appleNonDesktopTargets() {
    iosArm64()
    iosX64()
    iosSimulatorArm64()
}

fun KotlinMultiplatformExtension.appleTargets() {
    appleDesktopTargets()
    appleNonDesktopTargets()
}

fun KotlinMultiplatformExtension.desktopTargets() {
    appleDesktopTargets()
    nonAppleTargets()
}

fun KotlinMultiplatformExtension.nativeTargets() {
    appleTargets()
    nonAppleTargets()
}

fun KotlinMultiplatformExtension.allTargets() {
    jvm()
    jsTargets()
    nativeTargets()

    //will be replaced with hierarchy with kotlin 1.8.20
    sharedSourceSet("nonJvm") { it.platformType != KotlinPlatformType.jvm && it.platformType != KotlinPlatformType.common }
    setupSharedNativeSourceSets()
}
