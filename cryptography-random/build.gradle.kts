/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import org.jetbrains.kotlin.gradle.*
import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.konan.target.*

plugins {
    id("ckbuild.multiplatform-library")
}

description = "cryptography-kotlin random API"

@OptIn(ExperimentalKotlinGradlePluginApi::class)
kotlin {
    jvmTarget()
    jsTarget()
    nativeTargets()

    applyDefaultHierarchyTemplate {
        common {
            group("linuxAndAndroidNative") {
                withLinux()
                withAndroidNative()
            }
        }
    }

    targets.withType<KotlinNativeTarget>().matching {
        it.konanTarget.family == Family.LINUX || it.konanTarget.family == Family.ANDROID
    }.configureEach {
        cinterop("random", "linuxAndAndroidNative")
    }
}
