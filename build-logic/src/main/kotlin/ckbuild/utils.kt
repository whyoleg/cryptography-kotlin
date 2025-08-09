/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package ckbuild

import org.gradle.api.*
import org.gradle.api.artifacts.*
import org.gradle.api.provider.*
import org.gradle.kotlin.dsl.*

val Project.libsCatalog: VersionCatalog get() = extensions.getByName<VersionCatalogsExtension>("versionCatalogs").named("libs")

fun Project.versionCatalogLib(alias: String): Provider<MinimalExternalModuleDependency> = libsCatalog.findLibrary(alias).get()
