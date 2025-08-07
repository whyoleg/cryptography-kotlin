/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    alias(libs.plugins.kotlin.jvm)
}

dependencies {
    implementation(projects.api)
    implementation(libs.ktor.serialization.cbor)
    implementation(libs.ktor.server.core)
    implementation(libs.ktor.server.websockets)
    implementation(libs.ktor.server.cio)
    implementation(libs.ktor.server.calllogging)
    implementation(libs.ktor.server.cors)

    implementation(libs.logback.classic)
}
