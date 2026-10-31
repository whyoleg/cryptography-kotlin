/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    `kotlin-dsl`
}

dependencies {
    compileOnly(libs.kotlin.gradle.plugin)
    compileOnly(libs.android.gradle.plugin)

    implementation(project(":teststorage"))
}

gradlePlugin {
    plugins {
        create("ckbuild.provider-tests") {
            implementationClass = "ckbuild.providertests.ProviderTestsPlugin"
        }
    }
}
