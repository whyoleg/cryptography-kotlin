/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    `kotlin-dsl`
}

dependencies {
    implementation(kotlinLibs.gradle.plugin)

    implementation(libs.ktor.server.core)
    implementation(libs.ktor.server.netty)
    implementation(libs.ktor.server.calllogging)
    implementation(libs.ktor.server.cors)

    implementation(libs.logback.classic)

    implementation("build:build-parameters")
}

gradlePlugin {
    plugins {
        create("plugin") {
            id = "testtool-server"
            implementationClass = "dev.whyoleg.cryptography.testtool.server.TesttoolServerPlugin"
        }
    }
}
