/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    `kotlin-dsl`
}

kotlin {
    jvmToolchain(8)
}

dependencies {
    implementation("build:build-parameters")
}
