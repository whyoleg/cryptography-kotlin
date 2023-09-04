/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

pluginManagement {
    includeBuild("build-logic")
    includeBuild("build-settings")
}

includeBuild("testtool")

plugins {
    id("ckbuild.settings.default")
}

dependencyResolutionManagement {
    repositories {
        ivy("https://github.com/whyoleg/openssl-builds/releases/download") {
            name = "Prebuilt OpenSSL distributions"
            metadataSources { artifact() }
            content { includeGroup("ckbuild.dependencies.openssl") }
            patternLayout { artifact("[revision]/[artifact].[ext]") }
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
