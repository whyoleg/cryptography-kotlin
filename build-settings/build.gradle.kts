/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    `kotlin-dsl`
}

dependencies {
    implementation("com.gradle:develocity-gradle-plugin:4.0")
    implementation("com.gradle:common-custom-user-data-gradle-plugin:2.2.1")
    implementation("org.gradle.toolchains:foojay-resolver:0.10.0")
}
