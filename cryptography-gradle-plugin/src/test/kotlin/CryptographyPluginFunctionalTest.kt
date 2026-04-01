/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.gradle

import org.gradle.testkit.runner.*
import java.nio.file.*
import kotlin.test.*

class CryptographyPluginFunctionalTest {

    @Test
    fun testConfigureSwiftLinkerOpts() = forEachGradleVersion { gradleVersion ->
        val projectDir = createProjectDir()
        projectDir.resolve("build.gradle.kts").writeText(
            """
            plugins {
                kotlin("multiplatform") version "2.3.20"
                $`dev-whyoleg-cryptography`
            }

            kotlin {
                iosSimulatorArm64 {
                    binaries {
                        framework {
                            baseName = "TestFramework"
                        }
                    }
                }
            }

            cryptography {
                configureSwiftLinkerOpts.set(true)
            }

            tasks.register("verifyConfigured") {
                val target = kotlin.targets.getByName("iosSimulatorArm64") as org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget
                val framework = target.binaries.getFramework("DEBUG")
                val linkerOpts = framework.linkerOpts
                doLast {
                    println(linkerOpts)
                    if (${swiftLibrariesPath != null}) {
                        println("check linkerOpts")
                        check(linkerOpts.any { it.startsWith("-L${swiftLibrariesPath}/iphonesimulator") }) { "linker opts are not configured" }
                    }
                }
            }
            """.trimIndent()
        )

        val result = GradleRunner.create()
            .withGradleVersion(gradleVersion)
            .withProjectDir(projectDir)
            .withArguments("verifyConfigured", "--stacktrace", "--configuration-cache")
            .forwardOutput()
            .build()

        assertEquals(TaskOutcome.SUCCESS, result.task(":verifyConfigured")?.outcome)
    }

    @Test
    fun testConfigureSwiftLinkerOptsDisabled() = forEachGradleVersion { gradleVersion ->
        val projectDir = createProjectDir()
        projectDir.resolve("build.gradle.kts").writeText(
            """
            plugins {
                kotlin("multiplatform") version "2.3.20"
                $`dev-whyoleg-cryptography`
            }

            cryptography {
                // enable it first, and then add target, to check that we are doing it "lazy"
                configureSwiftLinkerOpts.set(true)
            }

            kotlin {
                iosSimulatorArm64 {
                    binaries {
                        framework {
                            baseName = "TestFramework"
                        }
                    }
                }
            }

            cryptography {
                configureSwiftLinkerOpts.set(false)
            }

            tasks.register("verifyConfigured") {
                val target = kotlin.targets.getByName("iosSimulatorArm64") as org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget
                val framework = target.binaries.getFramework("DEBUG")
                val linkerOpts = framework.linkerOpts
                doLast {
                    println(linkerOpts)
                    if (${swiftLibrariesPath != null}) {
                        println("check linkerOpts")
                        check(linkerOpts.none { it.startsWith("-L${swiftLibrariesPath}/iphonesimulator") }) { "linker opts are not configured" }
                    }
                }
            }
            """.trimIndent()
        )

        val result = GradleRunner.create()
            .withGradleVersion(gradleVersion)
            .withProjectDir(projectDir)
            .withArguments("verifyConfigured", "--stacktrace", "--configuration-cache")
            .forwardOutput()
            .build()

        assertEquals(TaskOutcome.SUCCESS, result.task(":verifyConfigured")?.outcome)
    }

    private val `dev-whyoleg-cryptography` get() = """id("dev.whyoleg.cryptography") version "${TestsArguments.devArtifactsVersion}""""

    private fun createProjectDir() = Files.createTempDirectory("cryptography-gradle-plugin-functional-test-").toFile().also { projectDir ->
        val devArtifactsRepositories =
            """
            exclusiveContent {
                filter { includeGroup("dev.whyoleg.cryptography") }
                forRepositories(
                    ${TestsArguments.devArtifactsDirectories.joinToString(",\n|        ") { "maven(\"$it\")" }}
                )
            }
            """.trimIndent()
        projectDir.resolve("settings.gradle.kts").writeText(
            """
            pluginManagement {
                repositories {
                    $devArtifactsRepositories
                    mavenCentral()
                }
            }    
            dependencyResolutionManagement {
                repositories {
                    $devArtifactsRepositories
                    mavenCentral()
                }
            }
            rootProject.name = "functional-test"
            """.trimIndent()
        )
    }

    private fun forEachGradleVersion(block: (gradleVersion: String) -> Unit) {
        val javaVersion = when (val specVersion = System.getProperty("java.specification.version")) {
            "1.8" -> 8
            else  -> specVersion.toInt()
        }
        // Latest stable releases for each major version
        mutableListOf<String>().apply {
            add("7.6.6")
            add("8.14.4")
            // Gradle 9+ requires Java 17+
            if (javaVersion >= 17) {
                add("9.4.1")
            }
        }.forEach {
            println("// RUN WITH GRADLE $it")
            block(it)
        }
    }

    companion object {
        private val swiftLibrariesPath: String? by lazy {
            if (!System.getProperty("os.name").contains("Mac", ignoreCase = true)) return@lazy null
            val process = ProcessBuilder("xcrun", "--find", "swift").start()
            if (process.waitFor() != 0) throw IllegalStateException("xcrun --find swift failed")
            process.inputStream.use {
                it.readBytes().decodeToString().substringBefore("\n")
            }.replace("/usr/bin/swift", "/usr/lib/swift")
        }
    }
}
