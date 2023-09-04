/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

pluginManagement {
    includeBuild("../build-settings")
}

plugins {
    id("ckbuild.settings.default")
}

dependencyResolutionManagement {
    repositories {
        gradlePluginPortal()
    }

    versionCatalogs {
        create("libs") {
            from(files("../gradle/libs.versions.toml"))
        }
    }
}

rootProject.name = "testtool"

include("client")
include("server")
include("plugin")
