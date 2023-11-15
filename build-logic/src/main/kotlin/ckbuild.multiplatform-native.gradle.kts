/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.gradle.targets.native.tasks.*
import org.jetbrains.kotlin.gradle.tasks.*

plugins {
    id("ckbuild.multiplatform")
}

kotlin {
    //setup tests running in RELEASE mode
    targets.withType<KotlinNativeTarget>().configureEach {
        binaries.test(listOf(NativeBuildType.RELEASE))
    }
    targets.withType<KotlinNativeTargetWithTests<*>>().configureEach {
        testRuns.create("releaseTest") {
            setExecutionSourceFrom(binaries.getTest(NativeBuildType.RELEASE))
        }
    }
}

tasks.register("nativeTest") {
    group = "verification"
    dependsOn(tasks.withType<KotlinNativeTest>().matching { it.enabled })
}

// on build, link even those binaries, which it's not possible to run
tasks.build {
    dependsOn(tasks.withType<KotlinNativeLink>())
}
