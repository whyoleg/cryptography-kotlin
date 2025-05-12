/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.swiftinterop

import dev.whyoleg.swiftinterop.tasks.*
import org.gradle.api.*
import org.gradle.api.tasks.*
import org.gradle.internal.os.*
import org.jetbrains.kotlin.gradle.dsl.*
import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.gradle.tasks.*

abstract class SwiftInteropPlugin : Plugin<Project> {
    private val isMacos = OperatingSystem.current().isMacOsX

    private fun Task.onlyIfMacos() {
        onlyIf { isMacos }
    }

    override fun apply(project: Project) {
        val swiftInterop = project.extensions.create("swiftInterop", SwiftInteropExtension::class.java)
        val buildDirectory = project.layout.buildDirectory.dir("swiftinterop")

        val generateSwiftCinteropDefinition = project.tasks.register(
            "generateSwiftCinteropDefinition",
            GenerateSwiftCinteropDefinitionTask::class.java
        ) { task ->
            task.group = "swiftinterop"
            task.onlyIfMacos()

            task.swiftinteropModuleName.set(swiftInterop.swiftinteropModuleName)
            task.packageName.set(swiftInterop.packageName)
            task.iosVersion.set(swiftInterop.iosVersion)
            task.macosVersion.set(swiftInterop.macosVersion)
            task.tvosVersion.set(swiftInterop.tvosVersion)
            task.watchosVersion.set(swiftInterop.watchosVersion)
            task.outputDirectory.set(buildDirectory.map { it.dir("cinterop") })
        }

        val generateSwiftPackageDefinition = project.tasks.register(
            "generateSwiftPackageDefinition",
            GenerateSwiftPackageDefinitionTask::class.java
        ) { task ->
            task.group = "swiftinterop"
            task.onlyIfMacos()

            task.swiftinteropModuleName.set(swiftInterop.swiftinteropModuleName)
            task.swiftToolsVersion.set(swiftInterop.swiftToolsVersion)
            task.iosVersion.set(swiftInterop.iosVersion)
            task.macosVersion.set(swiftInterop.macosVersion)
            task.tvosVersion.set(swiftInterop.tvosVersion)
            task.watchosVersion.set(swiftInterop.watchosVersion)
            task.outputDirectory.set(buildDirectory.map { it.dir("spm") })
        }

        val xcodebuildBuildOutputs = XcodebuildBuildTarget.Generic.values().associateWith { target ->
            val outputDirectory = buildDirectory.map { it.dir("xcodebuild/${target.disambiguationClassifier}") }

            outputDirectory to project.tasks.register(
                "${target.disambiguationClassifier}XcodebuildBuild",
                XcodebuildBuildTask::class.java,
            ) { task ->
                task.group = "swiftinterop"
                task.onlyIfMacos()

                task.swiftinteropModuleName.set(swiftInterop.swiftinteropModuleName)
                task.destination.set(target.destination)
                task.swiftPackageFile.set(generateSwiftPackageDefinition.map { it.swiftPackageFile.get() })
                task.swiftSources.from("src/commonMain/swift")
                task.outputDirectory.set(outputDirectory)
            }
        }

        project.extensions.configure<KotlinMultiplatformExtension>("kotlin") { kotlin ->
            kotlin.targets.withType(KotlinNativeTarget::class.java).all { nativeTarget ->
                if (!nativeTarget.konanTarget.family.isAppleFamily) return@all
                val targetInfo = XcodebuildBuildKonanTargetInfo(nativeTarget.konanTarget)
                val xcodebuildBuildOutput = xcodebuildBuildOutputs.getValue(targetInfo.target)

                val xcodeOutputDirectory = xcodebuildBuildOutput.first.map {
                    val buildFolderName = "${swiftInterop.swiftinteropModuleName.get()}.build"
                    it.dir("Build/Intermediates.noindex/$buildFolderName/${targetInfo.releaseFolder}/$buildFolderName/Objects-normal/${targetInfo.arch}")
                }

                val includeDirectory = buildDirectory.map { it.dir("outputs/${nativeTarget.disambiguationClassifier}/include") }
                val libsDirectory = buildDirectory.map { it.dir("outputs/${nativeTarget.disambiguationClassifier}/libs") }

                val copyObjectFiles = project.tasks.register(
                    "${nativeTarget.disambiguationClassifier}CopyObjectFiles",
                    Sync::class.java
                ) { task ->
                    task.group = "swiftinterop"
                    task.onlyIfMacos()
                    task.dependsOn(xcodebuildBuildOutput.second)

                    task.from(xcodeOutputDirectory) {
                        it.include("*.o")
                    }
                    task.into(buildDirectory.map { it.dir("outputs/${nativeTarget.disambiguationClassifier}/objects") })
                }

                val copyHeaderFiles = project.tasks.register(
                    "${nativeTarget.disambiguationClassifier}CopyHeaderFiles",
                    Sync::class.java
                ) { task ->
                    task.group = "swiftinterop"
                    task.onlyIfMacos()
                    task.dependsOn(xcodebuildBuildOutput.second)

                    task.from(xcodeOutputDirectory) {
                        it.include("*.h")
                    }
                    task.into(includeDirectory)
                }

                val libtoolBuildStatic = project.tasks.register(
                    "${nativeTarget.disambiguationClassifier}LibtoolBuildStatic",
                    LibtoolBuildStaticTask::class.java,
                ) { task ->
                    task.group = "swiftinterop"
                    task.onlyIfMacos()

                    task.swiftinteropModuleName.set(swiftInterop.swiftinteropModuleName)
                    task.objectFiles.from(copyObjectFiles)
                    task.outputDirectory.set(libsDirectory)
                }

                nativeTarget.compilations.getByName("main") { compilation ->
                    compilation.cinterops.create("swiftinterop") { cinterop ->
                        cinterop.definitionFile.set(generateSwiftCinteropDefinition.map { it.defFile.get() })
                        cinterop.compilerOpts.add("-I${includeDirectory.get().asFile.absolutePath}")
                        cinterop.extraOpts("-libraryPath", libsDirectory.get().asFile.absolutePath)

                        project.tasks.named(cinterop.interopProcessingTaskName, CInteropProcess::class.java) {
                            it.inputs.files(includeDirectory)
                            it.inputs.files(libsDirectory)
                            it.dependsOn(copyHeaderFiles, libtoolBuildStatic)
                        }
                    }
                }
            }
        }
    }
}
