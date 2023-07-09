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
    implementation("cryptography.build:build-parameters")
    implementation(kotlin("gradle-plugin"))
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
