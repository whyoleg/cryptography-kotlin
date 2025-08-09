/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import org.jetbrains.kotlin.gradle.*
import org.jetbrains.kotlin.gradle.dsl.*
import org.jetbrains.kotlin.gradle.targets.jvm.*
import org.jetbrains.kotlin.gradle.tasks.*

plugins {
    kotlin("multiplatform")
}

// true by default
val warningsAsErrors = providers.gradleProperty("ckbuild.warningsAsErrors").orNull?.toBoolean() ?: true

@OptIn(ExperimentalKotlinGradlePluginApi::class)
kotlin {
    // default JDK version
    jvmToolchain(8)

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
}

tasks.register("linkAll") {
    dependsOn(tasks.withType<KotlinNativeLink>())
}

if (providers.gradleProperty("ckbuild.skipLinkTasks").map(String::toBoolean).getOrElse(false)) {
    tasks.withType<KotlinNativeLink>().configureEach { onlyIf { false } }
}
