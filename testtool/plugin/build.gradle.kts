/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import org.jetbrains.kotlin.gradle.dsl.*

plugins {
    alias(kotlinLibs.plugins.jvm)
    `java-gradle-plugin`
}

kotlin {
    compilerOptions {
        languageVersion.set(KotlinVersion.KOTLIN_1_8)
        apiVersion.set(KotlinVersion.KOTLIN_1_8)
    }
}

dependencies {
    compileOnly(gradleKotlinDsl())
    compileOnly(kotlinLibs.gradle.plugin)
    implementation(projects.server)
    implementation(rootLibs.build.android)
}

gradlePlugin {
    plugins {
        create("testtool.server") {
            id = "testtool.server"
            implementationClass = "dev.whyoleg.cryptography.testtool.plugin.TesttoolServerPlugin"
        }
    }
}
