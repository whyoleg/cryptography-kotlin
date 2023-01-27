plugins {
    `java-platform`
    `maven-publish`
}

dependencies {
    constraints {
        rootProject.subprojects {
            if (plugins.hasPlugin("buildx-multiplatform-library")) api(project(path))
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
