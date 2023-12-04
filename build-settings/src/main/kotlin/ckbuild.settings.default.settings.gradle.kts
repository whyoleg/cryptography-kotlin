/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    id("ckbuild.settings.kotlin-version-catalog")
    id("com.gradle.enterprise")
    id("org.gradle.toolchains.foojay-resolver-convention")
}

pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
        google()
    }
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
        google()
    }
}

gradleEnterprise {
    buildScan {
        publishAlwaysIf(System.getenv("CI").toBoolean())
        termsOfServiceUrl = "https://gradle.com/terms-of-service"
        if (System.getenv("GITHUB_REPOSITORY") == "whyoleg/cryptography-kotlin") {
            termsOfServiceAgree = "yes"
        }
    }
}

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")
