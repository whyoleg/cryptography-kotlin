/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

pluginManagement {
    includeBuild("../build-settings")
    includeBuild("../testtool")
}

plugins {
    id("cksettings.default")
}

dependencyResolutionManagement {
    versionCatalogs.named("libs") {
        from(files("../gradle/libs.versions.toml"))
    }
}

rootProject.name = "build-logic"
