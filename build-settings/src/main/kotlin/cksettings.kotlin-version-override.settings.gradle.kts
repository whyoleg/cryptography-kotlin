/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

@file:Suppress("UnstableApiUsage")

// To use kotlin compiler built locally uncomment this
// or pass properties during build: `./gradlew TASK -Pckbuild.kotlinVersionOverride=2.5.255-SNAPSHOT -Pckbuild.kotlinRepositoryOverride=mavenLocal
//val kotlinVersionOverride = "2.5.255-SNAPSHOT"
//val kotlinRepositoryOverride = "mavenLocal"
val kotlinVersionOverride = providers.gradleProperty("ckbuild.kotlinVersionOverride").orNull?.takeIf(String::isNotBlank)
val kotlinRepositoryOverride = providers.gradleProperty("ckbuild.kotlinRepositoryOverride").orNull?.takeIf(String::isNotBlank)

// we need to create it eagerly to be able to override later
dependencyResolutionManagement {
    versionCatalogs.create("libs")
}

if (kotlinVersionOverride != null) {
    val kotlinDevRepository = kotlinRepositoryOverride ?: "https://redirector.kotlinlang.org/maven/dev"
    val kotlinGroup = "org.jetbrains.kotlin"

    logger.lifecycle("Kotlin version override: $kotlinVersionOverride, repository: $kotlinDevRepository")

    pluginManagement {
        repositories {
            if (kotlinDevRepository == "mavenLocal") mavenLocal {
                content { includeGroupAndSubgroups(kotlinGroup) }
            } else maven(kotlinDevRepository) {
                content { includeGroupAndSubgroups(kotlinGroup) }
            }
        }
    }

    dependencyResolutionManagement {
        repositories {
            if (kotlinDevRepository == "mavenLocal") mavenLocal {
                content { includeGroupAndSubgroups(kotlinGroup) }
            } else maven(kotlinDevRepository) {
                content { includeGroupAndSubgroups(kotlinGroup) }
            }
        }

        versionCatalogs.named("libs") {
            version("kotlin", kotlinVersionOverride)
        }
    }
}
