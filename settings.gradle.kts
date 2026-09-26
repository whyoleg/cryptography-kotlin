/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import cksettings.*

pluginManagement {
    includeBuild("build-logic")
    includeBuild("build-settings")

    // nested gradle plugins
    includeBuild("testtool")
    includeBuild("swiftinterop")
}

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

@Suppress("LocalVariableName")
projects("cryptography-kotlin") {
    // sync with build-logic/src/main/kotlin/ckbuild/Projects.kt
    // included into BOM, version catalog and Dokka
    val PUBLISHED_LIBRARY_WITH_DOCS = listOf("PUBLISHED_LIBRARY", "DOCUMENTED_LIBRARY")
    // only BOM and version catalog
    val PUBLISHED_LIBRARY_WITHOUT_DOCS = listOf("PUBLISHED_LIBRARY")

    // build-tools modules
    module("cryptography-bom")
    module("cryptography-version-catalog")

    // core util modules
    module("cryptography-bigint", PUBLISHED_LIBRARY_WITH_DOCS)
    module("cryptography-random", PUBLISHED_LIBRARY_WITH_DOCS)
    folder("cryptography-serialization") {
        module("pem", PUBLISHED_LIBRARY_WITH_DOCS) {
            module("benchmarks")
        }
        module("asn1", PUBLISHED_LIBRARY_WITH_DOCS) {
            module("modules", PUBLISHED_LIBRARY_WITH_DOCS)
        }
    }

    // providers API, high-level API
    module("cryptography-core", PUBLISHED_LIBRARY_WITH_DOCS)

    // providers
    folder("cryptography-providers", prefix = "cryptography-provider") {
        module("base", PUBLISHED_LIBRARY_WITHOUT_DOCS)
        module("tests")

        module("jdk", PUBLISHED_LIBRARY_WITHOUT_DOCS) {
            module("android-tests")
            // preconfigured JDK with BC provider
            module("bc", PUBLISHED_LIBRARY_WITHOUT_DOCS)
        }
        module("apple", PUBLISHED_LIBRARY_WITHOUT_DOCS)
        module("webcrypto", PUBLISHED_LIBRARY_WITHOUT_DOCS)
        folder("openssl3") {
            module("api", PUBLISHED_LIBRARY_WITHOUT_DOCS)
            module("shared", PUBLISHED_LIBRARY_WITHOUT_DOCS)
            module("prebuilt", PUBLISHED_LIBRARY_WITHOUT_DOCS)
            module("prebuilt-nativebuilds", PUBLISHED_LIBRARY_WITHOUT_DOCS)
        }
        module("cryptokit", PUBLISHED_LIBRARY_WITHOUT_DOCS)
        // composite provider
        module("optimal", PUBLISHED_LIBRARY_WITHOUT_DOCS)
    }

    // gradle plugin with helpers for swift and other things
    module("cryptography-gradle-plugin", PUBLISHED_LIBRARY_WITHOUT_DOCS)
}
