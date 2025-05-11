/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.swiftinterop.tasks

import org.gradle.api.*
import org.gradle.api.file.*
import org.gradle.api.provider.*
import org.gradle.api.tasks.*

abstract class GenerateSwiftPackageDefinitionTask : DefaultTask() {

    @get:Input
    abstract val swiftinteropModuleName: Property<String>

    @get:Input
    abstract val swiftToolsVersion: Property<String>

    @get:Input
    @get:Optional
    abstract val iosVersion: Property<String>

    @get:Input
    @get:Optional
    abstract val macosVersion: Property<String>

    @get:Input
    @get:Optional
    abstract val tvosVersion: Property<String>

    @get:Input
    @get:Optional
    abstract val watchosVersion: Property<String>

    @get:OutputDirectory
    abstract val outputDirectory: DirectoryProperty

    @get:Internal
    val swiftPackageFile: Provider<RegularFile> get() = outputDirectory.file("Package.swift")

    @TaskAction
    fun generate() {
        outputDirectory.get().asFile.recreateDirectories()

        val swiftinteropModuleName = swiftinteropModuleName.get()
        val platforms = listOfNotNull(
            iosVersion.orNull?.let { ".iOS(\"$it\")" },
            macosVersion.orNull?.let { ".macOS(\"$it\")" },
            tvosVersion.orNull?.let { ".tvOS(\"$it\")" },
            watchosVersion.orNull?.let { ".watchOS(\"$it\")" },
        ).joinToString(",")

        swiftPackageFile.get().asFile.writeText(
            """
            // swift-tools-version:${swiftToolsVersion.get()}
            import PackageDescription
        
            let package = Package(
                name: "$swiftinteropModuleName",
                platforms: [$platforms],
                products: [
                    .library(
                        name: "$swiftinteropModuleName",
                        type: .static,
                        targets: ["$swiftinteropModuleName"]
                    )
                ],
                dependencies: [],
                targets: [
                    .target(
                        name: "$swiftinteropModuleName"
                    )
                ]
            )
            """.trimIndent()
        )
    }
}
