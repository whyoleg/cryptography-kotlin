/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import org.jetbrains.kotlin.gradle.*

plugins {
    id("ckbuild.multiplatform-base")
    id("ckbuild.multiplatform-android")

    id("org.jetbrains.kotlin.plugin.serialization")
}

@OptIn(ExperimentalKotlinGradlePluginApi::class)
kotlin {
    jvmTarget()
    jsTarget()
    nativeTargets()
    wasmJsTarget()

    compilerOptions {
        optIn.addAll(
            OptIns.DelicateCryptographyApi,
            OptIns.CryptographyProviderApi,

            OptIns.ExperimentalStdlibApi,
            OptIns.ExperimentalEncodingApi,
        )
    }

    sourceSets {
        commonMain.dependencies {
            api(projects.cryptographyProvidersTestsApi)
        }
    }
}
