/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    alias(libs.plugins.kotlin.jvm)
    `java-gradle-plugin`
}

dependencies {
    compileOnly(kotlin("stdlib"))
    compileOnly(gradleKotlinDsl())
    compileOnly(libs.kotlin.gradle.plugin)
    compileOnly(libs.android.gradle.plugin)

    implementation(projects.server)
}

gradlePlugin {
    plugins {
        create("testtool.server") {
            id = "testtool.server"
            implementationClass = "dev.whyoleg.cryptography.testtool.plugin.TesttoolServerPlugin"
        }
    }
}
