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

    applyDefaultHierarchyTemplate {
        common {
            group("nonJs") {
                withJvm()
                withWasm()
                withNative()
                withAndroidTarget()
            }
        }
    }

    compilerOptions {
        optIn.addAll(
            OptIns.InsecureAlgorithm,
            OptIns.CryptographyProviderApi,

            OptIns.ExperimentalEncodingApi,
        )
    }

    sourceSets {
        commonMain.dependencies {
            api(kotlin("test"))

            api(projects.cryptographyCore)
            api(libs.kotlinx.coroutines.test)
            api(libs.kotlinx.serialization.json)

            implementation("testtool:client")
        }
        jsMain.dependencies {
            api(kotlin("test-js"))
        }
        jvmMain.dependencies {
            api(kotlin("test-junit"))
        }
        androidMain.dependencies {
            api(kotlin("test-junit"))
        }
    }
}
