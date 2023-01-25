import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.gradle.targets.jvm.*

plugins {
    kotlin("multiplatform")
}

kotlin {
    jvmToolchain(8)

    targets.all {
        if (this is KotlinNativeTargetWithTests<*>) setupTests()
        if (this is KotlinJvmTarget) setupTests()

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
        kotlin.setSrcDirs(listOf("$compilationName/sources/$targetName"))
        resources.setSrcDirs(listOf("$compilationName/resources/$targetName"))

        languageSettings {
            progressiveMode = true
            if (compilationName == "test") optInForTests()
        }

        //for some reason adding it to commonTest doesn't work
        if (compilationName == "test") when (targetName) {
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
