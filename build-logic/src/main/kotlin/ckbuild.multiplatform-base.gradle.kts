/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import org.jetbrains.kotlin.gradle.dsl.*
import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.gradle.targets.jvm.*
import org.jetbrains.kotlin.gradle.tasks.*

plugins {
    kotlin("multiplatform")
}

val warningsAsErrors = booleanProperty("ckbuild.warningsAsErrors", defaultValue = true)
val skipLinkTasks = booleanProperty("ckbuild.skipLinkTasks", defaultValue = false)


kotlin {
    compilerOptions {
        allWarningsAsErrors.set(warningsAsErrors)
        progressiveMode.set(true)
        freeCompilerArgs.add("-Xrender-internal-diagnostic-names")
    }

    targets.withType<KotlinJvmTarget>().configureEach {
        compilerOptions {
            jvmDefault = JvmDefaultMode.NO_COMPATIBILITY
        }
    }
    targets.withType<KotlinNativeTarget>().configureEach {
        compilations.configureEach {
            cinterops.configureEach {
                extraOpts += listOf("-Xccall-mode", "direct")
            }
        }
    }
}

tasks.register("linkAll") {
    dependsOn(tasks.withType<KotlinNativeLink>())
}

tasks.withType<KotlinNativeLink>().configureEach {
    val skipLinkTasks = skipLinkTasks // for CC
    onlyIf { !skipLinkTasks.get() }
}
