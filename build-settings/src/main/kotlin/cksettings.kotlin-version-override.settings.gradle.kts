/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

@file:Suppress("UnstableApiUsage")

val kotlinVersionOverride = providers.gradleProperty("ckbuild.kotlinVersionOverride").orNull?.takeIf(String::isNotBlank)

// we need to create it eagerly to be able to override later
dependencyResolutionManagement {
    versionCatalogs.create("libs")
}

if (kotlinVersionOverride != null) {
    val kotlinDevRepository = "https://maven.pkg.jetbrains.space/kotlin/p/kotlin/dev"
    val kotlinGroup = "org.jetbrains.kotlin"

    logger.lifecycle("Kotlin version override: $kotlinVersionOverride, repository: $kotlinDevRepository")

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
            version("kotlin", kotlinVersionOverride)
        }
    }
}
