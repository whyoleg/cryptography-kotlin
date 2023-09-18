/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import org.jetbrains.kotlin.gradle.*

plugins {
    kotlin("multiplatform")
    id("org.jetbrains.kotlinx.kover")
}

@OptIn(ExperimentalKotlinGradlePluginApi::class)
kotlin {
    jvmToolchain(8)

    applyDefaultHierarchyTemplate {
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
                withAndroidTarget()
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
