plugins {
    kotlin("multiplatform")
    id("org.jetbrains.kotlinx.kover")
}

kotlin {
    jvmToolchain(8)

    targets.all {
        compilations.all {
            compilerOptions.configure {
                freeCompilerArgs.add("-Xrender-internal-diagnostic-names")
            }
        }
    }

    sourceSets.all {
        val (targetName, compilationName) = name.run {
            val index = indexOfLast { it.isUpperCase() }
            take(index) to drop(index).toLowerCase() //.lowercase() //need Gradle 8
        }

        val isTest = compilationName == "test"

        languageSettings {
            progressiveMode = true
            if (isTest) optInForTests()
        }

        //for some reason adding it to commonTest only doesn't work
        if (isTest) when (targetName) {
            "common" -> "test"
            "jvm"    -> "test-junit"
            "js"     -> "test-js"
            else     -> null
        }?.let { testLibrary ->
            dependencies {
                implementation(kotlin(testLibrary))
            }
        }
    }
}
