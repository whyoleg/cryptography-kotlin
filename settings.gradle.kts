/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
    includeBuild("build-logic")
    includeBuild("build-parameters")
    includeBuild("build-kotlin")
    includeBuild("testtool-server")
}

plugins {
    id("kotlin-version-catalog")
    id("com.gradle.enterprise") version "3.12.2"
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }
}

gradleEnterprise {
    buildScan {
        termsOfServiceUrl = "https://gradle.com/terms-of-service"
        termsOfServiceAgree = "yes"
    }
}

rootProject.name = "cryptography-kotlin"

fun includeProvider(name: String, submodules: List<String> = emptyList()) {
    if (submodules.isEmpty()) {
        include("cryptography-$name")
        project(":cryptography-$name").projectDir = file("cryptography-providers/$name")
    } else {
        submodules.forEach { submodule ->
            include("cryptography-$name-$submodule")
            project(":cryptography-$name-$submodule").projectDir = file("cryptography-providers/$name/$submodule")
        }
    }
}

// support modules

include("cryptography-bom")
include("cryptography-version-catalog")

// core modules

include("cryptography-random")
include("cryptography-core")

// providers

includeProvider("jdk")
includeProvider("apple")
includeProvider("webcrypto")
includeProvider("openssl3", listOf("api", "shared", "prebuilt", "test"))

// testing

include("testtool-client")
include("test-support")
include("tests-compatibility")
