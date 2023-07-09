/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    //replace `kotlin` with `embeddedKotlin` with gradle 8.3
    kotlin("jvm") version "1.8.20"
}

kotlin {
    jvmToolchain(8)
}

dependencies {
    implementation(libs.ktor.server.core)
    implementation(libs.ktor.server.netty)
    implementation(libs.ktor.server.calllogging)
    implementation(libs.ktor.server.cors)

    implementation(libs.logback.classic)
}
