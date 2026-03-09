/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*

plugins {
    id("ckbuild.multiplatform-tests")
}

kotlin {
    nativeTargets()

    compilerOptions {
        optIn.addAll(
            OptIns.ExperimentalForeignApi,
        )
    }

    sourceSets.commonMain.dependencies {
        api(kotlin("test"))
        api(projects.cryptographyProviderOpenssl3Api)
    }
}
