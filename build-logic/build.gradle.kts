/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    `kotlin-dsl`
}

dependencies {
    implementation(kotlinLibs.gradle.plugin)
    implementation(libs.build.kotlinx.bcv)
    implementation(libs.build.kotlinx.kover)
    implementation(libs.build.kotlin.dokka)
    implementation(libs.build.gradle.download)
}
