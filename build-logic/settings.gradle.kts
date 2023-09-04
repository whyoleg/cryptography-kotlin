/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
        google()
    }
    includeBuild("../build-settings")
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
        google()
    }

    versionCatalogs {
        val libs by creating {
            from(files("../gradle/libs.versions.toml"))
        }
    }
}

plugins {
    id("kotlin-version-catalog")
}

rootProject.name = "build-logic"
