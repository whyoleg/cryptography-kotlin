plugins {
    `version-catalog`
    id("buildx-publish")
}

description = "cryptography-kotlin Gradle Version Catalog"

catalog {
    versionCatalog {
        //just a hint on version used by the library
        version("kotlin", kotlinLibs.versions.kotlin.get())
        version("cryptography", version.toString())
        rootProject.subprojects.forEach {
            if (it.name != "cryptography-version-catalog" &&
                evaluationDependsOn(it.path).plugins.hasPlugin("buildx-multiplatform-library")
            ) {
                library(it.name.substringAfter("cryptography-"), "dev.whyoleg.cryptography", it.name).versionRef("cryptography")
            }
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
