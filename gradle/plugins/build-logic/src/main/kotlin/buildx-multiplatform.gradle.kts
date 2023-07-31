/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import org.jetbrains.kotlin.gradle.*

plugins {
    kotlin("multiplatform")
    id("org.jetbrains.kotlinx.kover")
}

kotlin {
    jvmToolchain(8)

    @OptIn(ExperimentalKotlinGradlePluginApi::class)
    targetHierarchy.default {
        common {
            group("nonJvm") {
                withJs()
                withWasm()
                withNative()
            }
            group("nonJs") {
                withJvm()
                withWasm()
                withNative()
            }
        }
    }

    targets.configureEach {
        compilations.configureEach {
            compilerOptions.configure {
                progressiveMode.set(true)
                freeCompilerArgs.add("-Xrender-internal-diagnostic-names")
            }
        }
    }

    sourceSets {
        configureEach {
            languageSettings {
                // optIn in compilations are not propagated to IDE
                optIn("kotlinx.cinterop.ExperimentalForeignApi")
                if (name.contains("test", ignoreCase = true)) optInForTests()
            }
        }
        commonTest {
            dependencies {
                implementation(kotlin("test"))
            }
        }
    }
}
