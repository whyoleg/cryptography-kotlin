plugins {
    org.jetbrains.kotlin.multiplatform
}

kotlin {
    sourceSets {
        all {
            languageSettings {
                progressiveMode = true
            }
            val (targetName, compilationName) = name.run {
                val index = indexOfLast { it.isUpperCase() }
                take(index) to drop(index).lowercase()
            }
            kotlin.dir("$compilationName/sources/$targetName")
            resources.dir("$compilationName/resources/$targetName")
        }
    }
}
