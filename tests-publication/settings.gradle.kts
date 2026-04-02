/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }

    versionCatalogs {
        create("cryptographyLibs") {
            from("dev.whyoleg.cryptography:cryptography-version-catalog:0.6.0")
        }
    }
}

rootProject.name = "tests-publication"
