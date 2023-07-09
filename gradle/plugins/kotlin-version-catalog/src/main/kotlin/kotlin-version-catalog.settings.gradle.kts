/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    id("build-parameters")
}

val kotlinVersion = "1.9.0"
val kotlinVersionOverride = the<buildparameters.BuildParametersExtension>().useKotlin.orNull?.takeIf(String::isNotBlank)

if (kotlinVersionOverride != null) logger.lifecycle("Kotlin version override: $kotlinVersionOverride")

pluginManagement {
    if (kotlinVersionOverride != null) repositories {
        maven("https://maven.pkg.jetbrains.space/kotlin/p/kotlin/dev")
    }
}

dependencyResolutionManagement {
    if (kotlinVersionOverride != null) repositories {
        maven("https://maven.pkg.jetbrains.space/kotlin/p/kotlin/dev")
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
