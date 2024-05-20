/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package cksettings

import org.gradle.api.initialization.*

fun Settings.projects(rootProjectName: String, block: ProjectsScope.() -> Unit) {
    rootProject.name = rootProjectName
    ProjectsScope(settings, emptyList(), emptyList()).apply(block)
}

class ProjectsScope(
    private val settings: Settings,
    private val pathParts: List<String>,
    private val prefixParts: List<String>,
) {

    fun module(name: String) {
        val moduleName = (prefixParts + name).joinToString("-")
        val modulePath = (pathParts + name).joinToString("/")

        settings.include(moduleName)
        settings.project(":$moduleName").projectDir = settings.rootDir.resolve(modulePath)
    }

    fun module(name: String, prefix: String? = name, nested: ProjectsScope.() -> Unit = {}) {
        module(name)
        folder(name, prefix, nested)
    }

    fun folder(name: String, prefix: String? = name, block: ProjectsScope.() -> Unit) {
        val prefixParts = when (prefix) {
            null -> prefixParts
            else -> prefixParts + prefix
        }
        ProjectsScope(settings, pathParts + name, prefixParts).apply(block)
    }
}
