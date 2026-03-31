/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

@file:OptIn(ExperimentalAbiValidation::class)

import com.vanniktech.maven.publish.*
import org.jetbrains.kotlin.gradle.dsl.abi.*

plugins {
    id("ckbuild.multiplatform")
    id("ckbuild.kotlin-library")
}

kotlin {
    abiValidation {
        enabled = true
    }
}

mavenPublishing {
    configure(KotlinMultiplatform())
}
