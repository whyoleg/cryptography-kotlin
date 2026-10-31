/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    `kotlin-dsl`
    kotlin("plugin.serialization")
}

dependencies {
    compileOnly(libs.kotlin.gradle.plugin)
    compileOnly(libs.android.gradle.plugin)

    implementation(project(":teststorage"))
    implementation(libs.kotlinx.serialization.json)
}

gradlePlugin {
    plugins {
        create("ckbuild.provider-tests") {
            implementationClass = "ckbuild.providertests.ProviderTestsPlugin"
        }
        create("ckbuild.test-limitations") {
            implementationClass = "ckbuild.providertests.TestLimitationsPlugin"
        }
    }
}
