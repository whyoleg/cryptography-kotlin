/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import org.jetbrains.kotlin.gradle.*

plugins {
    id("ckbuild.multiplatform-library")
}

description = "cryptography-kotlin Apple provider"

@OptIn(ExperimentalKotlinGradlePluginApi::class)
kotlin {
    appleTargets()

    compilerOptions {
        optIn.addAll(
            OptIns.InsecureAlgorithm,
            OptIns.CryptographyProviderApi,

            OptIns.ExperimentalForeignApi,
        )
    }

    sourceSets.commonMain.dependencies {
        api(projects.cryptographyCore)
    }
}
