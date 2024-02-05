/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    id("com.gradle.enterprise")
    id("com.gradle.common-custom-user-data-gradle-plugin")
    id("org.gradle.toolchains.foojay-resolver-convention")
}

gradleEnterprise {
    buildScan {
        publishAlwaysIf(System.getenv("CI").toBoolean())
    }
}

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")
