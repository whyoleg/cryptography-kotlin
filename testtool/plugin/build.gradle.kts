/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import org.jetbrains.kotlin.gradle.dsl.*

plugins {
    alias(libs.plugins.kotlin.jvm)
    `java-gradle-plugin`
}

@Suppress("DEPRECATION")
kotlin {
    compilerOptions {
        languageVersion = KotlinVersion.KOTLIN_1_8
        apiVersion = KotlinVersion.KOTLIN_1_8
    }
}

dependencies {
    compileOnly(kotlin("stdlib"))
    compileOnly(gradleKotlinDsl())
    compileOnly(libs.kotlin.gradle.plugin)
    compileOnly(libs.android.gradle.plugin)

    implementation(projects.server)
}

gradlePlugin {
    plugins {
        create("testtool.server") {
            id = "testtool.server"
            implementationClass = "dev.whyoleg.cryptography.testtool.plugin.TesttoolServerPlugin"
        }
    }
}
