/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import org.jetbrains.kotlin.gradle.plugin.*

plugins {
    id("ckbuild.multiplatform")
    id("org.jetbrains.kotlinx.benchmark")
    kotlin("plugin.allopen")
}

allOpen {
    annotation("org.openjdk.jmh.annotations.State")
}

kotlin {
    // register benchmark targets - same as kotlin targets
    targets.all {
        if (platformType != KotlinPlatformType.common) benchmark.targets.register(name)
    }

    sourceSets {
        commonMain.dependencies {
            implementation(project.versionCatalogLib("kotlinx-benchmark-runtime"))
        }
    }
}
