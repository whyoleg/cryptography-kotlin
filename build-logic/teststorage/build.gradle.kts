/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    kotlin("jvm")
    `java-gradle-plugin`
}

dependencies {
    compileOnly(kotlin("stdlib"))
    compileOnly(gradleKotlinDsl())
    compileOnly(libs.kotlin.gradle.plugin)
    compileOnly(libs.android.gradle.plugin)

    implementation(libs.ktor.server.core)
    implementation(libs.ktor.server.cio)
    implementation(libs.ktor.server.cors)
}

gradlePlugin {
    plugins {
        create("ckbuild.teststorage") {
            implementationClass = "ckbuild.teststorage.TestStoragePlugin"
        }
    }
}
