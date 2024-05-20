/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    id("com.gradle.develocity")
    id("com.gradle.common-custom-user-data-gradle-plugin")
    id("org.gradle.toolchains.foojay-resolver-convention")
}

develocity {
    buildScan {
        publishing.onlyIf { System.getenv("CI").toBoolean() }
    }
}

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")
