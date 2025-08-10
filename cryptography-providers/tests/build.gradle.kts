/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import org.jetbrains.kotlin.gradle.*

plugins {
    id("ckbuild.multiplatform-tests")
    id("org.jetbrains.kotlin.plugin.serialization")
}

@OptIn(ExperimentalKotlinGradlePluginApi::class)
kotlin {
    allTargets(
        supportsWasmWasi = false,
    )

    compilerOptions {
        optIn.addAll(
            OptIns.DelicateCryptographyApi,
            OptIns.CryptographyProviderApi,
        )
        freeCompilerArgs.add("-Xexpect-actual-classes")
    }

    sourceSets {
        commonMain.dependencies {
            api(kotlin("test"))

            api(projects.cryptographyCore)
            api(projects.cryptographySerializationPem)
            api(projects.cryptographySerializationAsn1)
            api(projects.cryptographySerializationAsn1Modules)

            api(libs.kotlinx.coroutines.test)

            implementation("testtool:client")
        }
        jsMain.dependencies {
            api(kotlin("test-js"))
        }
        jvmMain.dependencies {
            api(kotlin("test-junit"))
        }
    }
}
