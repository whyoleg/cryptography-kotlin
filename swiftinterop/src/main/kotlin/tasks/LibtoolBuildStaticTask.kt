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

abstract class LibtoolBuildStaticTask : DefaultTask() {

    @get:Input
    abstract val swiftinteropModuleName: Property<String>

    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val objectFiles: ConfigurableFileCollection

    @get:OutputDirectory
    abstract val outputDirectory: DirectoryProperty

    @get:Inject
    abstract val exec: ExecOperations

    @TaskAction
    fun build() {
        outputDirectory.get().asFile.recreateDirectories()

        exec.exec { spec ->
            spec.commandLine(
                "libtool", "-static",
                "-o", outputDirectory.get().asFile.resolve("libswiftinterop_${swiftinteropModuleName.get()}.a").absolutePath,
                *objectFiles.asFileTree.map { it.absolutePath }.toTypedArray()
            )
        }
    }
}
