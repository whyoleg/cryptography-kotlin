/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import org.jetbrains.kotlin.gradle.dsl.*

plugins {
    alias(libs.plugins.kotlin.jvm)
    `java-gradle-plugin`
}

dependencies {
    implementation(libs.kotlin.gradle.plugin)
}

kotlin {
    compilerOptions {
        languageVersion.set(KotlinVersion.KOTLIN_1_8)
        apiVersion.set(KotlinVersion.KOTLIN_1_8)
    }
}

dependencies {
    compileOnly(kotlin("stdlib"))
    compileOnly(libs.kotlin.gradle.plugin)
}

gradlePlugin {
    plugins {
        create("swiftinterop") {
            id = "dev.whyoleg.swiftinterop"
            implementationClass = "dev.whyoleg.swiftinterop.SwiftInteropPlugin"
        }
    }
}
