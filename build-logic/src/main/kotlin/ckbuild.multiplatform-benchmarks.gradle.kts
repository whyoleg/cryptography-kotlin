/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import kotlinx.benchmark.gradle.*
import org.jetbrains.kotlin.gradle.plugin.*

plugins {
    id("ckbuild.multiplatform-base")
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

benchmark {
    targets.configureEach {
        if (this is JvmBenchmarkTarget) jmhVersion = "1.37"
    }
}
