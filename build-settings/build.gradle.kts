/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    `kotlin-dsl`
}

dependencies {
    implementation("com.gradle:develocity-gradle-plugin:4.1")
    implementation("com.gradle:common-custom-user-data-gradle-plugin:2.3")
    implementation("org.gradle.toolchains:foojay-resolver:1.0.0")
}
