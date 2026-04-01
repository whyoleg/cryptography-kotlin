/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

@file:OptIn(ExperimentalAbiValidation::class)

import org.jetbrains.kotlin.buildtools.api.*
import org.jetbrains.kotlin.gradle.*
import org.jetbrains.kotlin.gradle.dsl.*
import org.jetbrains.kotlin.gradle.dsl.abi.*

plugins {
    `java-gradle-plugin`
    kotlin("jvm")
    id("ckbuild.kotlin-library")
    id("com.gradle.plugin-publish")
}

kotlin {
    abiValidation {
        enabled = true
    }
    compilerOptions {
        freeCompilerArgs.add("-Xjdk-release=8")
        jvmTarget = JvmTarget.JVM_1_8
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

testing {
    @Suppress("UnstableApiUsage")
    suites.named("test", JvmTestSuite::class) {
        setOf(8, 11, 17).forEach { jdkTestVersion ->
            targets.register("test${jdkTestVersion}") {
                testTask.configure {
                    javaLauncher.set(javaToolchains.launcherFor {
                        languageVersion.set(JavaLanguageVersion.of(jdkTestVersion))
                    })
                }
            }
        }
    }
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

// aggregate task for CI

tasks.register("jvmAllTest") {
    group = "verification"
    dependsOn(tasks.withType<Test>())

    finalizedBy("koverVerify")
}