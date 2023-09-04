/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
        google()
    }

    includeBuild("../build-settings")
}

plugins {
    id("kotlin-version-catalog")
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
        google()
    }

    versionCatalogs {
        val libs by creating {
            from(files("libs.versions.toml"))
        }
        val rootLibs by creating {
            from(files("../gradle/libs.versions.toml"))
        }
    }
}

rootProject.name = "testtool"

includeBuild("../build-parameters")

include("client")
include("server")
include("plugin")
