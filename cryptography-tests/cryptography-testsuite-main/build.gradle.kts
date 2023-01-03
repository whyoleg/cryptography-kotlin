import org.jetbrains.kotlin.gradle.plugin.*

plugins {
    id("buildx-multiplatform")
}

kotlin {
    jvm()
    val jsTargets = listOf(
        js("nodejs") {
            nodejs {
                testTask {
                    useMocha {
                        timeout = "600s"
                    }
                }
            }
            attributes {
                attribute(Attribute.of("js.target", String::class.java), "nodejs")
            }
        },
        js("browser") {
            browser {
                testTask {
                    useKarma {
                        useConfigDirectory(project.jsDir("karma.config.d"))
                        useChromeHeadless()
//                        useSafari()
                    }
                }
            }
            attributes {
                attribute(Attribute.of("js.target", String::class.java), "browser")
            }
        }
    )

    val linuxTargets = listOf(linuxX64())
    val darwinTargets = listOf(macosX64(), macosArm64())
    val mingwTargets = listOf(mingwX64())

    sourceSets {
        commonMain {
            dependencies {
                api(projects.cryptographyCore)
                api(projects.cryptographyRandom)
            }
        }
        commonTest {
            dependencies {
                implementation(libs.kotlinx.coroutines.test)
                implementation(kotlin("test"))
            }
        }
        fun shared(name: String, targets: List<KotlinTarget>) {
            val main = create("${name}Main") {
                dependsOn(commonMain.get())
            }
            val test = create("${name}Test") {
                dependsOn(commonTest.get())
            }
            targets.forEach {
                getByName("${it.name}Main").dependsOn(main)
                getByName("${it.name}Test").dependsOn(test)
            }
        }
        shared("js", jsTargets)
        shared("linux", linuxTargets)
        shared("darwin", darwinTargets)
        shared("mingw", mingwTargets)

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

fun Project.jsDir(folder: String): File = rootDir.resolve("gradle").resolve(folder)
