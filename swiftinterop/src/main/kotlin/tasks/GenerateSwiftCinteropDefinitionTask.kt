/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.swiftinterop.tasks

import org.gradle.api.*
import org.gradle.api.file.*
import org.gradle.api.provider.*
import org.gradle.api.tasks.*

abstract class GenerateSwiftCinteropDefinitionTask : DefaultTask() {

    @get:Input
    abstract val swiftinteropModuleName: Property<String>

    @get:Input
    abstract val packageName: Property<String>

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
    val defFile: Provider<RegularFile> get() = outputDirectory.file("${swiftinteropModuleName.get()}.def")

    @TaskAction
    fun generate() {
        outputDirectory.get().asFile.recreateDirectories()

        defFile.get().asFile.writeText(
            """
            language = Objective-C
            package = ${packageName.get()}
            headers = ${swiftinteropModuleName.get()}-Swift.h
            staticLibraries = libswiftinterop_${swiftinteropModuleName.get()}.a
            
            # linker options for Swift
            linkerOpts.osx = ${linkerOpts("macos", "macosx", macosVersion)}
            
            linkerOpts.ios_arm64 = ${linkerOpts("ios", "iphoneos", iosVersion)}
            linkerOpts.ios_x64 = ${linkerOpts("ios-simulator", "iphonesimulator", iosVersion)}
            linkerOpts.ios_simulator_arm64 = ${linkerOpts("ios-simulator", "iphonesimulator", iosVersion)}
            
            linkerOpts.watchos_arm32 = ${linkerOpts("watchos", "watchos", watchosVersion)}
            linkerOpts.watchos_arm64 = ${linkerOpts("watchos", "watchos", watchosVersion)}
            linkerOpts.watchos_device_arm64 = ${linkerOpts("watchos", "watchos", watchosVersion)}
            linkerOpts.watchos_x64 = ${linkerOpts("watchos-simulator", "watchsimulator", watchosVersion)}
            linkerOpts.watchos_simulator_arm64 = ${linkerOpts("watchos-simulator", "watchsimulator", watchosVersion)}
            
            linkerOpts.tvos_arm64 = ${linkerOpts("tvos", "appletvos", tvosVersion)}
            linkerOpts.tvos_x64 = ${linkerOpts("tvos-simulator", "appletvsimulator", tvosVersion)}
            linkerOpts.tvos_simulator_arm64 = ${linkerOpts("tvos-simulator", "appletvsimulator", tvosVersion)}
            """.trimIndent()
        )
    }

    private fun linkerOpts(
        os: String,
        libsDir: String,
        version: Provider<String>,
    ): String {
        val developerDir = System.getenv("DEVELOPER_DIR") ?: "/Applications/Xcode.app/Contents/Developer"
        val linker = "-L$developerDir/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift/$libsDir/"
        val v = version.orNull ?: return linker
        return "-platform_version $os ${v}.0 ${v}.0 $linker"
    }
}
