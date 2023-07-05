/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    kotlin("multiplatform")
    id("org.jetbrains.kotlinx.kover")
}

kotlin {
    jvmToolchain(8)

    targets.all {
        compilations.all {
            compilerOptions.configure {
                freeCompilerArgs.addAll(
                    "-Xrender-internal-diagnostic-names",
                    "-Xjvm-default=all"
                )
            }
        }
    }

    sourceSets.all {
        val (targetName, compilationName) = name.run {
            val index = indexOfLast { it.isUpperCase() }
            take(index) to drop(index).lowercase()
        }

        val isTest = compilationName == "test"

        languageSettings {
            progressiveMode = true

            optIn("kotlinx.cinterop.ExperimentalForeignApi")
            optIn("kotlin.experimental.ExperimentalNativeApi")

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
