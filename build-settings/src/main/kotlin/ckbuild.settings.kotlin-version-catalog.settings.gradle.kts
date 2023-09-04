/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.settings.*

val kotlinVersionOverride = providers.gradleProperty("useKotlin").orNull?.takeIf(String::isNotBlank)

if (kotlinVersionOverride != null) logger.lifecycle("Kotlin version override: $kotlinVersionOverride")

pluginManagement {
    if (kotlinVersionOverride != null) repositories {
        maven("https://maven.pkg.jetbrains.space/kotlin/p/kotlin/dev") {
            content {
                includeGroup("org.jetbrains.kotlin")
            }
        }
    }
}

dependencyResolutionManagement {
    if (kotlinVersionOverride != null) repositories {
        maven("https://maven.pkg.jetbrains.space/kotlin/p/kotlin/dev") {
            content {
                includeGroup("org.jetbrains.kotlin")
            }
        }
    }
    versionCatalogs {
        create("kotlinLibs") {
            val kotlin = version("kotlin", kotlinVersionOverride ?: kotlinVersion)

            library("gradle-plugin", "org.jetbrains.kotlin", "kotlin-gradle-plugin").versionRef(kotlin)

            plugin("multiplatform", "org.jetbrains.kotlin.multiplatform").versionRef(kotlin)
            plugin("jvm", "org.jetbrains.kotlin.jvm").versionRef(kotlin)
            plugin("serialization", "org.jetbrains.kotlin.plugin.serialization").versionRef(kotlin)
        }
    }
}
