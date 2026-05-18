/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

@file:Suppress("UnstableApiUsage")

// allows overriding kotlin version and maven repository used through the whole build
val kotlinVersion = providers.gradleProperty("kotlin_version").orNull?.takeIf(String::isNotBlank)
val kotlinRepoUrl = providers.gradleProperty("kotlin_repo_url").orNull?.takeIf(String::isNotBlank)

// we need to create it eagerly to be able to override later
dependencyResolutionManagement {
    versionCatalogs.create("libs")
}

if (kotlinVersion != null) {
    val kotlinDevRepository = kotlinRepoUrl ?: "https://redirector.kotlinlang.org/maven/dev"
    val kotlinGroup = "org.jetbrains.kotlin"

    logger.lifecycle("Kotlin version override: $kotlinVersion, repository: $kotlinDevRepository")

    pluginManagement {
        repositories {
            maven(kotlinDevRepository) {
                content { includeGroupAndSubgroups(kotlinGroup) }
            }
        }
    }

    dependencyResolutionManagement {
        repositories {
            maven(kotlinDevRepository) {
                content { includeGroupAndSubgroups(kotlinGroup) }
            }
        }

        versionCatalogs.named("libs") {
            version("kotlin", kotlinVersion)
        }
    }
}
