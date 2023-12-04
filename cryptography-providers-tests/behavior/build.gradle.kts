/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import org.jetbrains.kotlin.gradle.*

plugins {
    id("ckbuild.multiplatform-base")
    id("ckbuild.multiplatform-android")
}

@OptIn(ExperimentalKotlinGradlePluginApi::class)
kotlin {
    jvmTarget()
    jsTarget()
    nativeTargets()

    compilerOptions {
        optIn.addAll(
            OptIns.CryptographyProviderApi,
            OptIns.InsecureAlgorithm,

            OptIns.ExperimentalEncodingApi,
        )
    }

    sourceSets.commonTest.dependencies {
        implementation(projects.cryptographyProvidersTestsSupport)
    }
}
