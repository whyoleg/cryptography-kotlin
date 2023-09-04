/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import org.jetbrains.kotlin.gradle.plugin.*
import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.gradle.targets.native.tasks.*

plugins {
    id("ckbuild.multiplatform")
}

kotlin {
    targets.withType<KotlinNativeTargetWithTests<*>>().configureEach {
        //setup tests running in RELEASE mode
        binaries.test(listOf(NativeBuildType.RELEASE))
        testRuns.create("releaseTest") {
            setExecutionSourceFrom(binaries.getTest(NativeBuildType.RELEASE))
        }
        //don't even link tests if we can't run them (like, linux on macos, or mingw on linux/macos, etc)
        testRuns.configureEach {
            executionSource.binary.linkTaskProvider.get().enabled = (this as ExecutionTaskHolder<*>).executionTask.get().enabled
        }
    }
}

tasks.register("nativeTest") {
    group = "verification"
    dependsOn(tasks.withType<KotlinNativeTest>())
}
