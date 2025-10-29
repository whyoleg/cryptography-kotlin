/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*

plugins {
    id("ckbuild.multiplatform-benchmarks")
}

kotlin {
    compilerOptions {
        allWarningsAsErrors = false // TODO
    }
    allBenchmarkTargets()

    sourceSets {
        commonMain.dependencies {
            implementation(projects.cryptographySerializationPem)
        }
    }
}
