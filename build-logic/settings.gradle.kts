/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import cksettings.*

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

projects("build-logic") {
    module("teststorage")
}
