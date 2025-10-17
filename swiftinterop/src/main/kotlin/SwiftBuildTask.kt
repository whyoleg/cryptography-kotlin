/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.swiftinterop

import org.gradle.api.*
import org.gradle.api.file.*
import org.gradle.api.provider.*
import org.gradle.api.provider.Provider
import org.gradle.api.tasks.*
import org.gradle.process.*
import org.jetbrains.kotlin.konan.target.*
import javax.inject.*

@CacheableTask
abstract class SwiftBuildTask : DefaultTask() {

//  injects

    @get:Inject
    abstract val exec: ExecOperations

    @get:Inject
    abstract val fs: FileSystemOperations

    @get:Inject
    abstract val providers: ProviderFactory

//  inputs

    // release or debug
    @get:Input
    abstract val configuration: Property<String>

    @get:Input
    abstract val swiftTargetTriple: Property<SwiftTargetTriple>

    @get:Input
    abstract val swiftProduct: Property<String>

    @get:InputDirectory
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val swiftProjectDirectory: DirectoryProperty

//  outputs

    @get:OutputDirectory
    abstract val outputDirectory: DirectoryProperty

    @get:Internal
    val libsDirectory get() = outputDirectory.dir("libs")

    @get:Internal
    val includeDirectory get() = outputDirectory.dir("include")

    @TaskAction
    fun build() {
        outputDirectory.get().asFile.deleteRecursively()

        val swiftProjectDirectory = swiftProjectDirectory.get().asFile
        val swiftTargetTriple = swiftTargetTriple.get()
        val swiftProduct = swiftProduct.get()
        val configuration = configuration.get()

        val buildDirectory = temporaryDir.resolve(".build")
        val targetBuildDirectory = buildDirectory.resolve("$swiftTargetTriple/$configuration")

        val sdkPath = providers.exec {
            it.commandLine(
                "xcrun",
                "--sdk", swiftTargetTriple.sdk.sdk,
                "--show-sdk-path"
            )
        }.standardOutput.asText.get().substringBefore("\n") // take the first line

        exec.exec {
            it.commandLine(
                "swift", "build",
                "--quiet",
                "--configuration", configuration,
                "--package-path", swiftProjectDirectory,
                "--build-path", buildDirectory,
                "--triple", swiftTargetTriple,
                "--sdk", sdkPath,
                "--product", swiftProduct
            )
        }

        fs.sync {
            it.from(targetBuildDirectory.resolve("${swiftProduct}.build/include"))
            it.into(includeDirectory)
            it.include("*.h")
        }

        fs.sync {
            it.from(targetBuildDirectory)
            it.into(libsDirectory)
            it.include("*.a")
        }
    }

    companion object {
        fun registerIn(
            project: Project,
            productName: String,
            konanTarget: KonanTarget,
            disambiguatedName: String,
            swiftProjectDirectory: Provider<Directory>,
            configure: SwiftBuildTask.() -> Unit = {},
        ): TaskProvider<SwiftBuildTask> = project.tasks.register(
            disambiguatedName + "SwiftBuild" + productName.replaceFirstChar(Char::uppercase),
            SwiftBuildTask::class.java
        ) { task ->
            task.onlyIfMacos()

            task.group = "swiftInterop"
            task.outputDirectory.set(project.layout.buildDirectory.dir("swiftInterop/$productName/swift-build/$disambiguatedName"))
            task.outputDirectory.finalizeValue()
            task.configuration.convention("release")

            task.swiftTargetTriple.set(SwiftTargetTriple.from(konanTarget))
            task.swiftProduct.set(productName)
            task.swiftProjectDirectory.set(swiftProjectDirectory)

            task.configure()
        }
    }
}
