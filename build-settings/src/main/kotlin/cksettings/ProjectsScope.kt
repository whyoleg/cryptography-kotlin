/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package cksettings

import org.gradle.api.initialization.*

@Suppress("UnstableApiUsage")
fun Settings.projects(rootProjectName: String, block: ProjectsScope.() -> Unit = {}) {
    rootProject.name = rootProjectName
    // sync with build-logic/src/main/kotlin/ckbuild/Projects.kt
    val projectsByTag = mutableMapOf<String, MutableSet<String>>()
    ProjectsScope(settings, emptyList(), emptyList(), projectsByTag).apply(block)

    gradle.lifecycle.beforeProject {
        projectsByTag.forEach { (tag, projectNames) ->
            extensions.extraProperties["ckbuild.projects.$tag"] = projectNames
        }
    }
}

class ProjectsScope(
    private val settings: Settings,
    private val pathParts: List<String>,
    private val prefixParts: List<String>,
    private val projectsByTag: MutableMap<String, MutableSet<String>>,
) {

    fun module(name: String, vararg tags: String): Unit = module(name, tags.toList())

    fun module(name: String, tags: List<String> = emptyList()) {
        val moduleName = (prefixParts + name).joinToString("-")
        val modulePath = (pathParts + name).joinToString("/")

        settings.include(moduleName)
        settings.project(":$moduleName").projectDir = settings.rootDir.resolve(modulePath)

        tags.forEach { tag ->
            projectsByTag.getOrPut(tag, ::mutableSetOf).add(moduleName)
        }
    }

    fun module(
        name: String,
        vararg tags: String,
        prefix: String? = name,
        nested: ProjectsScope.() -> Unit = {},
    ): Unit = module(name, tags.toList(), prefix, nested)

    fun module(name: String, tags: List<String>, prefix: String? = name, nested: ProjectsScope.() -> Unit = {}) {
        module(name, tags)
        folder(name, prefix, nested)
    }

    fun folder(name: String, prefix: String? = name, block: ProjectsScope.() -> Unit) {
        val prefixParts = when (prefix) {
            null -> prefixParts
            else -> prefixParts + prefix
        }
        ProjectsScope(settings, pathParts + name, prefixParts, projectsByTag).apply(block)
    }
}
