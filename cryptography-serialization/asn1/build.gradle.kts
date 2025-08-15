/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import org.jetbrains.kotlin.gradle.*

plugins {
    id("ckbuild.multiplatform-library")
    id("org.jetbrains.kotlin.plugin.serialization")
}

description = "cryptography-kotlin ASN.1 (DER) API"

@OptIn(ExperimentalKotlinGradlePluginApi::class)
kotlin {
    allTargets()

    applyDefaultHierarchyTemplate {
        common {
            group("nonConcurrent") {
                withJs()
                withWasmJs()
                withWasmWasi()
            }
        }
    }

    sourceSets {
        commonMain.dependencies {
            api(projects.cryptographyBigint)
            api(libs.kotlinx.serialization.core)
            api(libs.kotlinx.io.core)
        }
    }
}
