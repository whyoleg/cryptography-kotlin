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

rootProject.name = "build-kotlin"

includeBuild("../build-parameters") {
    dependencySubstitution {
        substitute(module("build:build-parameters")).using(project(":"))
    }
}
