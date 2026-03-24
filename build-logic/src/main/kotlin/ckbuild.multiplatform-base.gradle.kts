/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.gradle.tasks.*

plugins {
    kotlin("multiplatform")
}

val warningsAsErrors = booleanProperty("ckbuild.warningsAsErrors", defaultValue = true)
val skipLinkTasks = booleanProperty("ckbuild.skipLinkTasks", defaultValue = false)
val skipReleaseLinkTasks = booleanProperty("ckbuild.skipReleaseLinkTasks", defaultValue = false)

kotlin {
    compilerOptions {
        allWarningsAsErrors.set(warningsAsErrors)
        progressiveMode.set(true)
        freeCompilerArgs.addAll(
            "-Xrender-internal-diagnostic-names",
            "-Xexpect-actual-classes",
            "-Xreturn-value-checker=full"
        )
    }
}

tasks.register("linkAll") {
    dependsOn(tasks.withType<KotlinNativeLink>())
}

tasks.withType<KotlinNativeLink>().configureEach {
    val isRelease = binary.buildType == NativeBuildType.RELEASE
    val skipLinkTasks = skipLinkTasks // for CC
    val skipReleaseLinkTasks = skipReleaseLinkTasks // for CC
    onlyIf { !skipLinkTasks.get() }
    if (isRelease) onlyIf { !skipReleaseLinkTasks.get() }
}
