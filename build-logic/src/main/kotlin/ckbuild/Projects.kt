/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package ckbuild

import org.gradle.api.*

// sync tags with settings.gradle.kts
@Suppress("UNCHECKED_CAST")
private fun Project.projectNames(tag: String): Set<String> {
    return (extensions.extraProperties["ckbuild.projects.$tag"] as? Set<String>).orEmpty()
}

fun Project.publishedLibrariesProjectNames(): Set<String> = projectNames("PUBLISHED_LIBRARY")

fun Project.documentedLibrariesProjectNames(): Set<String> = projectNames("DOCUMENTED_LIBRARY")
