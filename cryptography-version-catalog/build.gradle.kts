/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*

plugins {
    `version-catalog`
    id("ckbuild.publication")
}

description = "cryptography-kotlin Gradle Version Catalog"

catalog {
    versionCatalog {
        val cryptographyVersion = version("cryptography", version.toString())
        Projects.published.forEach { name ->
            if (project.name == name) return@forEach // skip version catalog :)
            library(
                /* alias =    */ name.substringAfter("cryptography-"),
                /* group =    */ "dev.whyoleg.cryptography",
                /* artifact = */ name
            ).versionRef(cryptographyVersion)
        }
    }
}

publishing {
    publications {
        val versionCatalog by creating(MavenPublication::class) {
            from(components["versionCatalog"])
        }
    }
}
