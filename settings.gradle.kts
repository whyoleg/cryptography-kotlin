/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

pluginManagement {
    includeBuild("build-logic")
    includeBuild("build-settings")
}

includeBuild("testtool")

plugins {
    id("cksettings.default")
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

projects {
    // build-tools modules
    module("cryptography-bom")
    module("cryptography-version-catalog")

    // core util modules
    module("cryptography-bigint")
    module("cryptography-random")
    folder("cryptography-serialization") {
        module("pem")
        module("asn1") {
            module("modules")
        }
    }

    // providers API, high-level API
    module("cryptography-core")

    // providers
    folder("cryptography-providers", prefix = "cryptography-provider") {
        module("jdk") {
            module("android-tests")
        }
        module("apple")
        module("webcrypto")
        folder("openssl3") {
            module("api")
            module("shared")
            module("prebuilt")
            module("test")
        }
    }

    // providers tests
    module("cryptography-providers-tests-api")
    module("cryptography-providers-tests")
}

fun projects(block: ProjectsScope.() -> Unit) {
    ProjectsScope(emptyList(), emptyList()).apply(block)
}

class ProjectsScope(private val pathParts: List<String>, private val prefixParts: List<String>) {

    fun module(name: String) {
        val moduleName = (prefixParts + name).joinToString("-")
        val modulePath = (pathParts + name).joinToString("/")

        include(moduleName)
        project(":$moduleName").projectDir = file(modulePath)
    }

    fun module(name: String, prefix: String = name, nested: ProjectsScope.() -> Unit = {}) {
        module(name)
        folder(name, prefix, nested)
    }

    fun folder(name: String, prefix: String = name, block: ProjectsScope.() -> Unit) {
        ProjectsScope(pathParts + name, prefixParts + prefix).apply(block)
    }
}
