/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    `kotlin-dsl`
}

dependencies {
    implementation(kotlinLibs.gradle.plugin)
    implementation(libs.kotlinx.bcv)
    implementation(libs.kotlinx.kover)
    implementation(libs.kotlin.dokka)
    implementation(libs.gradle.download)
}
