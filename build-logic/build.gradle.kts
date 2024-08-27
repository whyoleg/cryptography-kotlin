/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    `kotlin-dsl`
}

dependencies {
    implementation(libs.kotlin.gradle.plugin)
    implementation(libs.kotlin.dokka.gradle.plugin)
    implementation(libs.kotlin.dokka.core)
    implementation(libs.kotlinx.bcv.gradle.plugin)
    implementation(libs.kotlinx.kover.gradle.plugin)
    implementation(libs.android.gradle.plugin)
    implementation(libs.maven.publish.gradle.plugin)
    implementation(libs.apache.commons.compress)
    implementation("testtool:plugin")
}
