/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import org.jetbrains.kotlin.gradle.*
import org.jetbrains.kotlin.gradle.plugin.*

plugins {
    id("ckbuild.multiplatform-library")
}

description = "cryptography-kotlin core API"

kotlin {
    jvmTarget()
    jsTarget()
    nativeTargets()
    wasmTargets()

    @OptIn(ExperimentalKotlinGradlePluginApi::class)
    applyDefaultHierarchyTemplate {
        common {
            group("nonJvm") {
                withCompilations { it.platformType != KotlinPlatformType.jvm }
            }
        }
    }

    sourceSets.commonMain.dependencies {
        api(projects.cryptographyBigint)
        api(projects.cryptographyRandom)
    }
}
