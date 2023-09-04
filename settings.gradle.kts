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
    includeBuild("build-parameters")
    includeBuild("build-logic")
    includeBuild("kotlin-version-catalog")
}

includeBuild("testtool")

plugins {
    id("kotlin-version-catalog")
    id("com.gradle.enterprise") version "3.14.1"
    id("org.gradle.toolchains.foojay-resolver-convention") version "0.7.0"
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
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

rootProject.name = "cryptography-kotlin"

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

// providers tests

listOf(
    "support",
    "behavior",
    "compatibility"
).forEach { name ->
    includeWithPath(
        "cryptography-providers-tests-$name",
        "cryptography-providers-tests/$name"
    )
}

// utils

fun includeProvider(name: String, submodules: List<String> = emptyList()) {
    if (submodules.isEmpty()) {
        includeWithPath(
            "cryptography-provider-$name",
            "cryptography-providers/$name"
        )
    } else {
        submodules.forEach { submodule ->
            includeWithPath(
                "cryptography-provider-$name-$submodule",
                "cryptography-providers/$name/$submodule"
            )
        }
    }
}

fun includeWithPath(name: String, path: String) {
    include(name)
    project(":$name").projectDir = file(path)
}
