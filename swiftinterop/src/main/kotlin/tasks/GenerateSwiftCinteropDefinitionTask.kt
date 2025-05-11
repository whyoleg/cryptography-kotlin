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
            # linkerOpts = -L/usr/lib/swift
            linkerOpts.osx = -L/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift/macosx
            linkerOpts.ios_arm64 = -L/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift/iphoneos/
            linkerOpts.ios_x64 = -L/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift/iphonesimulator/
            linkerOpts.ios_simulator_arm64 = -L/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift/iphonesimulator/
            linkerOpts.watchos_arm32 = -L/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift/watchos/
            linkerOpts.watchos_arm64 = -L/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift/watchos/
            linkerOpts.watchos_device_arm64 = -L/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift/watchos/
            linkerOpts.watchos_x64 = -L/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift/watchsimulator/
            linkerOpts.watchos_simulator_arm64 = -L/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift/watchsimulator/
            linkerOpts.tvos_arm64 = -L/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift/appletvos/
            linkerOpts.tvos_x64 = -L/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift/appletvsimulator/
            linkerOpts.tvos_simulator_arm64 = -L/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift/appletvsimulator/
            """.trimIndent()
        )
    }
}
