/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    `kotlin-dsl`
    alias(libs.plugins.buildconfig)
}

dependencies {
    implementation(libs.build.gradle.enterprise)
    implementation(libs.build.gradle.foojay)
}

buildConfig {
    packageName("ckbuild.settings")
    useKotlinOutput {
        topLevelConstants = true
        internalVisibility = true
    }
    buildConfigField("kotlinVersion", libs.versions.kotlin.asProvider())
}
