/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    `kotlin-dsl`
}

dependencies {
    implementation("com.gradle:gradle-enterprise-gradle-plugin:3.17.5")
    implementation("com.gradle:common-custom-user-data-gradle-plugin:2.0.2")
    implementation("org.gradle.toolchains:foojay-resolver:0.8.0")
}
