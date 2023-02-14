pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

rootProject.name = "kotlin-version-catalog"

includeBuild("../build-parameters") {
    dependencySubstitution {
        substitute(module("build:build-parameters")).using(project(":"))
    }
}
