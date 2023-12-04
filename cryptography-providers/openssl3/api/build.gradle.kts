/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import org.jetbrains.kotlin.gradle.*
import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.gradle.tasks.*

plugins {
    id("ckbuild.multiplatform-library")
    id("ckbuild.use-openssl")
}

description = "cryptography-kotlin OpenSSL3 provider (API)"

@OptIn(ExperimentalKotlinGradlePluginApi::class)
kotlin {
    nativeTargets()

    compilerOptions {
        optIn.addAll(
            OptIns.InsecureAlgorithm,
            OptIns.CryptographyProviderApi,

            OptIns.ExperimentalForeignApi,
        )
    }

    sourceSets.commonMain.dependencies {
        api(projects.cryptographyCore)
    }

    targets.withType<KotlinNativeTarget>().configureEach {
        cinterop("declarations", "common")
    }
}

tasks.withType<CInteropProcess>().configureEach {
    dependsOn(tasks.setupOpenssl3)
    settings.includeDirs(openssl3.includeDirectory(konanTarget))
}

documentation {
    moduleName.set("cryptography-provider-openssl3")
    includes.set("../README.md")
}
