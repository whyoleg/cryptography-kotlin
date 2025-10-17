/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.swiftinterop

import org.gradle.api.*
import org.gradle.api.Named
import org.gradle.api.file.*
import org.jetbrains.kotlin.gradle.plugin.*
import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.gradle.tasks.*
import javax.inject.*

abstract class SwiftInteropProduct @Inject internal constructor(
    val productName: String,
    project: Project,
) : Named {
    override fun getName(): String = productName

    val swiftProjectDirectory: DirectoryProperty = project.objects.directoryProperty()
        .convention(project.layout.projectDirectory.dir("swift"))

    private val cInteropDefinitionTask = GenerateSwiftCInteropDefinitionTask.registerIn(project, productName)

    internal fun setupCInterop(
        compilation: KotlinNativeCompilation,
        block: CInteropSettings.() -> Unit,
    ) {
        val project = compilation.project

        val swiftBuild = SwiftBuildTask.registerIn(
            project = project,
            productName = productName,
            konanTarget = compilation.konanTarget,
            disambiguatedName = compilation.disambiguatedName,
            swiftProjectDirectory = swiftProjectDirectory
        )
        compilation.cinterops.create("swiftInterop${productName.replaceFirstChar(Char::uppercase)}") {
            it.definitionFile.set(cInteropDefinitionTask.map { it.defFile.get() })
            it.definitionFile.finalizeValue()

            it.block()

            project.tasks.named(it.interopProcessingTaskName, CInteropProcess::class.java) { cinteropTask ->
                cinteropTask.dependsOn(cInteropDefinitionTask)
                cinteropTask.dependsOn(swiftBuild)
                cinteropTask.inputs.files(swiftBuild.flatMap { it.outputDirectory })
                cinteropTask.settings.includeDirs(swiftBuild.flatMap { it.includeDirectory })
                cinteropTask.settings.extraOpts("-libraryPath", swiftBuild.flatMap { it.libsDirectory }.get().asFile.absolutePath)
            }
        }
    }

    companion object {
        fun factory(project: Project): NamedDomainObjectFactory<SwiftInteropProduct> = NamedDomainObjectFactory { name ->
            project.objects.newInstance(SwiftInteropProduct::class.java, name, project)
        }
    }
}
