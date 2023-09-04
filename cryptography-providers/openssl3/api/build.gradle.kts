/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.gradle.tasks.*

plugins {
    id("buildx-multiplatform-provider")
    id("buildx-target-native-all")
    id("buildx-use-openssl")
}

description = "cryptography-kotlin OpenSSL3 provider (API)"

tasks.withType<CInteropProcess>().configureEach {
    dependsOn(tasks.setupOpenssl3)
    settings.includeDirs(openssl3.includeDirectory(konanTarget))
}

kotlin {
    targets.withType<KotlinNativeTarget>().configureEach {
        cinterop("declarations", "common")
    }
}

documentation {
    moduleName.set("cryptography-provider-openssl3")
    includes.set("../README.md")
}
