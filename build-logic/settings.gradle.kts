/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
    includeBuild("../build-kotlin")
}

dependencyResolutionManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }

    versionCatalogs {
        val libs by creating {
            from(files("libs.versions.toml"))
        }
    }
}

plugins {
    id("kotlin-version-catalog")
}

rootProject.name = "build-logic"
