/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
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

includeProvider("jdk", submodules = listOf("android-tests"))
includeProvider("apple")
includeProvider("webcrypto")
includeProvider(
    name = "openssl3",
    includeSelf = false,
    submodules = listOf("api", "shared", "prebuilt", "test")
)

// providers tests

include("cryptography-providers-tests-api")
include("cryptography-providers-tests")

// utils

fun includeProvider(
    name: String,
    includeSelf: Boolean = true,
    submodules: List<String> = emptyList(),
) {
    if (includeSelf) includeWithPath(
        name = "cryptography-provider-$name",
        path = "cryptography-providers/$name"
    )
    submodules.forEach { submodule ->
        includeWithPath(
            "cryptography-provider-$name-$submodule",
            "cryptography-providers/$name/$submodule"
        )
    }
}

fun includeWithPath(name: String, path: String) {
    include(name)
    project(":$name").projectDir = file(path)
}
