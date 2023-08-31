/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
        google()
    }
    includeBuild("../kotlin-version-catalog")
}

dependencyResolutionManagement {
    repositories {
        // TODO: temporary dev version
        maven("https://maven.pkg.jetbrains.space/kotlin/p/dokka/dev") {
            content { includeGroup("org.jetbrains.dokka") }
        }
        mavenCentral()
        gradlePluginPortal()
        google()
    }

    versionCatalogs {
        val libs by creating {
            from(files("../../libs.versions.toml"))
        }
    }
}

plugins {
    id("kotlin-version-catalog")
}

rootProject.name = "build-logic"
