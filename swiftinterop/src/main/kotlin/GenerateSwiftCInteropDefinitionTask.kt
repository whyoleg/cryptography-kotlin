/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.swiftinterop

import org.gradle.api.*
import org.gradle.api.file.*
import org.gradle.api.provider.*
import org.gradle.api.tasks.*

@CacheableTask
abstract class GenerateSwiftCInteropDefinitionTask : DefaultTask() {

    @get:Input
    abstract val swiftProductName: Property<String>

    @get:OutputDirectory
    abstract val outputDirectory: DirectoryProperty

    @get:Internal
    val defFile: Provider<RegularFile> get() = outputDirectory.file("${swiftProductName.get()}.def")

    @TaskAction
    fun generate() {
        outputDirectory.get().asFile.recreateDirectories()

        defFile.get().asFile.writeText(
            """
            language = Objective-C
            
            headers = ${swiftProductName.get()}-Swift.h
            staticLibraries = lib${swiftProductName.get()}.a
            
            # linker options for Swift
            linkerOpts.osx = ${linkerOpts("macosx")}
            
            linkerOpts.ios_arm64 = ${linkerOpts("iphoneos")}
            linkerOpts.ios_x64 = ${linkerOpts("iphonesimulator")}
            linkerOpts.ios_simulator_arm64 = ${linkerOpts("iphonesimulator")}
            
            linkerOpts.watchos_arm32 = ${linkerOpts("watchos")}
            linkerOpts.watchos_arm64 = ${linkerOpts("watchos")}
            linkerOpts.watchos_device_arm64 = ${linkerOpts("watchos")}
            linkerOpts.watchos_x64 = ${linkerOpts("watchsimulator")}
            linkerOpts.watchos_simulator_arm64 = ${linkerOpts("watchsimulator")}
            
            linkerOpts.tvos_arm64 = ${linkerOpts("appletvos")}
            linkerOpts.tvos_x64 = ${linkerOpts("appletvsimulator")}
            linkerOpts.tvos_simulator_arm64 = ${linkerOpts("appletvsimulator")}
            """.trimIndent()
        )
    }

    // this path could be different on user machines
    private fun linkerOpts(libsDir: String): String {
        return "-L/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift/$libsDir/"
    }

    companion object {
        fun registerIn(
            project: Project,
            productName: String,
            configure: GenerateSwiftCInteropDefinitionTask.() -> Unit = {},
        ): TaskProvider<GenerateSwiftCInteropDefinitionTask> = project.tasks.register(
            "generateSwiftCInteropDefinition" + productName.replaceFirstChar(Char::uppercase),
            GenerateSwiftCInteropDefinitionTask::class.java
        ) { task ->
            task.onlyIfMacos()

            task.group = "swiftInterop"
            task.outputDirectory.set(project.layout.buildDirectory.dir("swiftInterop/$productName/cinterop"))
            task.outputDirectory.finalizeValue()

            task.swiftProductName.set(productName)

            task.configure()
        }
    }
}
