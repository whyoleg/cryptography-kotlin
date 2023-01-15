import org.jetbrains.kotlin.gradle.dsl.*

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

fun KotlinMultiplatformExtension.darwinTargets() {
    macosX64()
    macosArm64()
}

fun KotlinMultiplatformExtension.allTargets() {
    jvm()
    jsTargets()
    darwinTargets()
    linuxX64()
    mingwX64()
}
