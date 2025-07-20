/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import org.jetbrains.kotlin.gradle.*

plugins {
    id("ckbuild.multiplatform-library")
}

description = "cryptography-kotlin core API"

kotlin {
    allTargets()

    @OptIn(ExperimentalKotlinGradlePluginApi::class)
    applyDefaultHierarchyTemplate {
        common {
            group("nonJvm") {
                withJs()
                withWasmJs()
                withWasmWasi()
                group("native")
            }
        }
    }

    sourceSets.commonMain.dependencies {
        api(projects.cryptographyBigint)
        api(projects.cryptographyRandom)
        api(libs.kotlinx.io.core)
    }
}
