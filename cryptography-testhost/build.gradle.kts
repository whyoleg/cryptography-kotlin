/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import org.jetbrains.kotlin.gradle.*

plugins {
    id("ckbuild.multiplatform")
    id("org.jetbrains.kotlin.plugin.serialization")
    id("ckbuild.teststorage")
}

kotlin {
    allTargets(
        supportsWasmWasi = false,
    )

    @OptIn(ExperimentalKotlinGradlePluginApi::class)
    applyDefaultHierarchyTemplate {
        common {
            // http storage
            group("http") {
                // for android
                withJvm()
                group("web")
            }
            // filesystem storage
            group("filesystem") {
                withJvm()
                group("native")
            }
        }
    }

    sourceSets {
        commonMain.dependencies {
            api(libs.kotlinx.serialization.core)
        }

        named("filesystemMain").dependencies {
            implementation(libs.kotlinx.io.core)
        }
        named("httpMain").dependencies {
            implementation(libs.ktor.client.core)
        }
        jvmMain.dependencies {
            implementation(libs.ktor.client.cio)
        }

        commonTest.dependencies {
            implementation(libs.kotlinx.coroutines.test)
        }
    }
}
