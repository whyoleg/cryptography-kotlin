plugins {
    org.jetbrains.kotlin.multiplatform
}

kotlin {
    explicitApi()
    sourceSets {
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
            }
        }

        all {
            val suffixIndex = name.indexOfLast { it.isUpperCase() }
            val targetName = name.substring(0, suffixIndex)
            val suffix = name.substring(suffixIndex).toLowerCase()
            val (srcPath, resourcesPath) = when (suffix) {
                "main" -> "src" to "resources"
                else   -> suffix to "${suffix}Resources"
            }
            kotlin.setSrcDirs(listOf("$targetName/$srcPath"))
            resources.setSrcDirs(listOf("$targetName/$resourcesPath"))

            languageSettings {
                progressiveMode = true

                optIn("kotlin.RequiresOptIn")

                if (suffix == "test") {
                    optIn("kotlinx.coroutines.ExperimentalCoroutinesApi")
                }
            }
        }
    }
}
