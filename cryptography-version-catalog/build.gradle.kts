/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    `version-catalog`
    id("ckbuild.publication")
}

description = "cryptography-kotlin Gradle Version Catalog"

catalog {
    versionCatalog {
        //just a hint on version used by the library
        version("kotlin", kotlinLibs.versions.kotlin.get())
        val cryptographyVersion = version("cryptography", version.toString())
        (ckbuild.bom.artifacts + "cryptography-bom").forEach { name ->
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
