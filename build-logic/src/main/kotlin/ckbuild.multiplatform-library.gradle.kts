/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

@file:OptIn(ExperimentalAbiValidation::class)

import org.jetbrains.kotlin.gradle.dsl.abi.*

plugins {
    id("ckbuild.multiplatform-base")
    id("ckbuild.multiplatform-tests")
    id("ckbuild.publication")
    id("ckbuild.documentation")
}

kotlin {
    explicitApi()
    abiValidation {
        enabled = true
    }
}

tasks.check {
    dependsOn(tasks.checkLegacyAbi)
}
