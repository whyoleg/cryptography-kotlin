plugins {
    `java-platform`
    id("buildx-publish")
}

description = "cryptography-kotlin BOM"

dependencies {
    constraints {
        rootProject.subprojects.forEach {
            if (it.name !in setOf("cryptography-bom", "cryptography-version-catalog") &&
                evaluationDependsOn(it.path).plugins.hasPlugin("buildx-multiplatform-library")
            ) {
                api(project(it.path))
            }
        }
    }
}

publishing {
    publications {
        val bom by creating(MavenPublication::class) {
            from(components["javaPlatform"])
        }
    }
}
