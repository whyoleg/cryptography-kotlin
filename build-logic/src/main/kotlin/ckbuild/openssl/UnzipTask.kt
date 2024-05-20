/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package ckbuild.openssl

import org.apache.commons.compress.archivers.zip.*
import org.gradle.api.*
import org.gradle.api.file.*
import org.gradle.api.tasks.*
import java.nio.file.*
import kotlin.io.path.*

// Gradle zipTree doesn't support symlinks
abstract class UnzipTask : DefaultTask() {

    @get:InputFile
    abstract val inputFile: RegularFileProperty

    @get:OutputDirectory
    abstract val outputDirectory: DirectoryProperty

    @OptIn(ExperimentalPathApi::class)
    @TaskAction
    fun unzipAction() {
        val outputRoot = outputDirectory.get().asFile.toPath()
        outputRoot.deleteRecursively()
        @Suppress("DEPRECATION")
        ZipFile(inputFile.get().asFile).use { zipFile ->
            val entries = zipFile.entries
            while (entries.hasMoreElements()) {
                val zipEntry = entries.nextElement()
                val path = outputRoot.resolve(zipEntry.name)
                path.parent.createDirectories()
                when {
                    zipEntry.isUnixSymlink -> path.createSymbolicLinkPointingTo(Paths.get(zipFile.getUnixSymlink(zipEntry)))
                    !zipEntry.isDirectory  -> zipFile.getInputStream(zipEntry).use { inputStream ->
                        path.outputStream().use { outputStream ->
                            inputStream.copyTo(outputStream)
                        }
                    }
                }
            }
        }
    }
}
