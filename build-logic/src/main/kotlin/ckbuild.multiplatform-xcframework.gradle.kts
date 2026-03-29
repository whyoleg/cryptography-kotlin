/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.gradle.plugin.mpp.apple.*

plugins {
    id("ckbuild.multiplatform")
}

kotlin {
    val staticXcf = XCFramework("static")
    val dynamicXcf = XCFramework("dynamic")

    targets.withType<KotlinNativeTarget>().matching {
        it.konanTarget.family.isAppleFamily
    }.configureEach {
        binaries.framework("static") {
            isStatic = true
            staticXcf.add(this)
        }
        binaries.framework("dynamic") {
            isStatic = false
            dynamicXcf.add(this)
        }
    }
}

tasks.named("linkAll") {
    dependsOn(tasks.withType<XCFrameworkTask>())
}
