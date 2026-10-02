/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*

plugins {
    id("ckbuild.multiplatform")
    id("org.jetbrains.kotlin.plugin.serialization")
}

kotlin {
    allTargets(
        supportsWasmWasi = false,
    )

    sourceSets {
        commonMain.dependencies {
            api(libs.kotlinx.serialization.core)
        }
    }
}
