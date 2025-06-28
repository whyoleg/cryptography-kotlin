/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import ckbuild.openssl.*
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
            OptIns.DelicateCryptographyApi,
            OptIns.CryptographyProviderApi,

            OptIns.ExperimentalForeignApi,
        )
    }

    sourceSets.commonMain.dependencies {
        api(projects.cryptographyCore)
        implementation(projects.cryptographyProviderBase)
    }

    targets.withType<KotlinNativeTarget>().configureEach {
        cinterop("declarations", "common")
    }
}

tasks.withType<CInteropProcess>().configureEach {
    uses(openssl.v3_0) {
        settings.includeDirs(includeDirectory(konanTarget))
    }
}
