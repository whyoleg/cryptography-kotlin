/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.swiftinterop.tasks

import org.gradle.api.*
import org.gradle.api.file.*
import org.gradle.api.provider.*
import org.gradle.api.tasks.*
import org.gradle.process.*
import javax.inject.*

abstract class XcodebuildBuildTask : DefaultTask() {

    @get:Input
    abstract val swiftinteropModuleName: Property<String>

    @get:Input
    abstract val destination: Property<String>

    @get:InputFile
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val swiftPackageFile: RegularFileProperty

    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val swiftSources: ConfigurableFileCollection

    @get:OutputDirectory
    abstract val outputDirectory: DirectoryProperty

    @get:Inject
    abstract val exec: ExecOperations

    @TaskAction
    fun build() {
        outputDirectory.get().asFile.recreateDirectories()
        temporaryDir.recreateDirectories()

        swiftPackageFile.get().asFile.copyTo(temporaryDir.resolve("Package.swift"))
        swiftSources.asFileTree.forEach {
            it.copyTo(temporaryDir.resolve("Sources").resolve(swiftinteropModuleName.get()).resolve(it.name))
        }

        exec.exec {
            it.workingDir(temporaryDir)
            val developerDir = System.getenv("DEVELOPER_DIR") ?: ""
            val forceNoCompat = listOf("SWIFT_RUNTIME_COMPATIBILITY_VERSION=none")
            val base = mutableListOf(
                "xcodebuild", "build",
                "-scheme", swiftinteropModuleName.get(),
                "-configuration", "Release",
                "-derivedDataPath", outputDirectory.get().asFile.absolutePath,
                "-destination", destination.get()
            )
            // Prefer setting runtime compatibility to none for newer toolchains (Xcode 26+)
            // We conservatively always append it; older toolchains ignore unknown setting.
            base.addAll(forceNoCompat)
            it.commandLine(base)
        }
    }
}
