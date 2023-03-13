plugins {
    `version-catalog`
    id("buildx-publish")
}

description = "cryptography-kotlin Gradle Version Catalog"

catalog {
    versionCatalog {
        //just a hint on version used by the library
        version("kotlin", kotlinLibs.versions.kotlin.get())
        val cryptographyVersion = version("cryptography", version.toString())
        (bom.libraries + ":cryptography-bom").forEach {
            val name = it.substringAfterLast(":")
            library(
                /* alias = */ name.substringAfter("cryptography-"),
                /* group = */ "dev.whyoleg.cryptography",
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
