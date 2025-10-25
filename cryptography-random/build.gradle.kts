/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import org.jetbrains.kotlin.gradle.*

plugins {
    id("ckbuild.multiplatform-library")
}

description = "cryptography-kotlin random API"

@OptIn(ExperimentalKotlinGradlePluginApi::class)
kotlin {
    allTargets()

    compilerOptions {
        freeCompilerArgs.add("-Xexpect-actual-classes")
    }

    applyDefaultHierarchyTemplate {
        common {
            group("linuxAndAndroidNative") {
                group("linux")
                group("androidNative")
            }
        }
    }
}
