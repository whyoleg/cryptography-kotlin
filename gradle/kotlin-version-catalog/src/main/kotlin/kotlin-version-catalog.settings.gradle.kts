plugins {
    id("build-parameters")
}

dependencyResolutionManagement {
    versionCatalogs {
        create("kotlinLibs") {
            val kotlinVersionDefault = "1.8.0"

            val kotlinVersionOverride = the<buildparameters.BuildParametersExtension>().kotlin.override.version.orNull
            if (kotlinVersionOverride != null) logger.lifecycle("Kotlin version override: $kotlinVersionOverride")
            val kotlin = version("kotlin", kotlinVersionOverride ?: kotlinVersionDefault)

            library("gradle-plugin", "org.jetbrains.kotlin", "kotlin-gradle-plugin").versionRef(kotlin)

            plugin("multiplatform", "org.jetbrains.kotlin.multiplatform").versionRef(kotlin)
            plugin("serialization", "org.jetbrains.kotlin.plugin.serialization").versionRef(kotlin)
        }
    }
}
