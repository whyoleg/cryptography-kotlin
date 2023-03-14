/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.konan.target.*

plugins {
    id("buildx-multiplatform-native")
    id("buildx-target-native-apple")
    id("buildx-target-native-desktop")
}

kotlin {
    sharedSourceSet("native") { it is KotlinNativeTarget }
    sharedSourceSet("mingw") { (it as? KotlinNativeTarget)?.konanTarget?.family == Family.MINGW }
    sharedSourceSet("linux") { (it as? KotlinNativeTarget)?.konanTarget?.family == Family.LINUX }
    sharedSourceSet("darwin") { (it as? KotlinNativeTarget)?.konanTarget?.family?.isAppleFamily == true }
}
