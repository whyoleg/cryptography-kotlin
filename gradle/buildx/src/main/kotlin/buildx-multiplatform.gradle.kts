import org.jetbrains.kotlin.gradle.plugin.*
import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.gradle.targets.jvm.*

plugins {
    kotlin("multiplatform")
}

kotlin {
    jvmToolchain(8)

    sourceSets {
        all {
            languageSettings {
                progressiveMode = true
            }
            val (targetName, compilationName) = name.run {
                val index = indexOfLast { it.isUpperCase() }
                take(index) to drop(index).lowercase()
            }
            kotlin.dir("$compilationName/sources/$targetName")
            resources.dir("$compilationName/resources/$targetName")
        }
    }
    targets.all {
        if (this is KotlinNativeTargetWithTests<*>) {
            //setup additional running in RELEASE move for Native targets
            binaries.test(listOf(NativeBuildType.RELEASE))
            testRuns.create("releaseTest") {
                setExecutionSourceFrom(binaries.getTest(NativeBuildType.RELEASE))
            }
            //don't even link tests if we can't run them (like, linux on macos, or mingw on linux/macos, etc)
            testRuns.all {
                if (this is ExecutionTaskHolder<*>) {
                    executionSource.binary.linkTaskProvider.get().enabled = executionTask.get().enabled
                }
            }
        } else if (this is KotlinJvmTarget) {
            //setup additional testing on different JDK versions (default task jvmTest will run on JDK8)
            listOf(11, 17).forEach { jdkVersion ->
                testRuns.create("${jdkVersion}Test") {
                    executionTask.configure {
                        javaLauncher.set(
                            javaToolchains.launcherFor {
                                languageVersion.set(JavaLanguageVersion.of(jdkVersion))
                            }
                        )
                    }
                }
                testRuns.all {
                    executionTask.configure {
                        // ActiveProcessorCount is used here, to make sure local setup is similar as on CI
                        // Github Actions linux runners have 2 cores
                        jvmArgs("-Xmx4g", "-XX:ActiveProcessorCount=2")
                    }
                }
            }
        }
    }
}
