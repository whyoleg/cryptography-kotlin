/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import org.jetbrains.kotlin.buildtools.api.*
import org.jetbrains.kotlin.gradle.*
import org.jetbrains.kotlin.gradle.dsl.*

plugins {
    `java-gradle-plugin`
    kotlin("jvm")
    id("ckbuild.kotlin-library")
    id("com.gradle.plugin-publish")
}

dependencies {
    compileOnly(kotlin("stdlib"))
    compileOnly(kotlin("gradle-plugin"))
}

@OptIn(ExperimentalBuildToolsApi::class, ExperimentalKotlinGradlePluginApi::class)
kotlin {
    compilerVersion = "2.0.21" // to be able to use AV/LV 1.4 for Gradle 7+ compatibility
    compilerOptions {
        // progressiveMode works only for latest kotlin version
        progressiveMode.set(false)
        languageVersion.set(KotlinVersion.KOTLIN_1_4)
        apiVersion.set(KotlinVersion.KOTLIN_1_4)
        freeCompilerArgs.addAll(
            "-Xsuppress-version-warnings",
            "-Xskip-metadata-version-check"
        )
    }
}

gradlePlugin {
    website = "https://whyoleg.github.io/cryptography-kotlin/"
    vcsUrl = "https://github.com/whyoleg/cryptography-kotlin.git"
}
