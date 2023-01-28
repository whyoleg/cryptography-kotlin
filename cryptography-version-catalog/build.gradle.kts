plugins {
    `version-catalog`
    `maven-publish`
}

catalog {
    versionCatalog {
        //just a hint on version used by the library
        version("kotlin", libs.versions.kotlin.asProvider().get())
        version("cryptography", version.toString())
        rootProject.subprojects.forEach {
            if (it.name !in setOf("cryptography-bom", "cryptography-version-catalog") &&
                evaluationDependsOn(it.path).plugins.hasPlugin("buildx-multiplatform-library")
            ) {
                library(it.name.substringAfter("cryptography-"), "dev.whyoleg.cryptography", it.name).versionRef("cryptography")
            }
        }
    }
}

publishing {
    publications {
        val catalog by creating(MavenPublication::class) {
            from(components["versionCatalog"])
        }
    }
}
