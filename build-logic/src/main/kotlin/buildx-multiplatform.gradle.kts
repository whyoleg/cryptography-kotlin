/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import org.jetbrains.kotlin.gradle.*
import org.jetbrains.kotlin.gradle.plugin.*

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
                withCompilations {
                    it.platformType != KotlinPlatformType.jvm &&
                            it.platformType != KotlinPlatformType.androidJvm &&
                            it.platformType != KotlinPlatformType.common
                }
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
                optIn("kotlin.experimental.ExperimentalNativeApi")
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
