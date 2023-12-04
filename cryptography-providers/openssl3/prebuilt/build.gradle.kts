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

description = "cryptography-kotlin OpenSSL3 provider (prebuilt)"

@OptIn(ExperimentalKotlinGradlePluginApi::class)
kotlin {
    nativeTargets()

    compilerOptions {
        optIn.addAll(
            OptIns.ExperimentalForeignApi,
        )
    }

    sourceSets {
        commonMain.dependencies {
            api(projects.cryptographyProviderOpenssl3Api)
        }
        commonTest.dependencies {
            api(projects.cryptographyProviderOpenssl3Test)
        }
    }

    targets.withType<KotlinNativeTarget>().configureEach {
        cinterop("linking", "common")
    }
}

tasks.withType<CInteropProcess>().configureEach {
    dependsOn(tasks.setupOpenssl3)
    settings.extraOpts("-libraryPath", openssl3.libDirectory(konanTarget).get().asFile.absolutePath)
}

documentation {
    includes.set(null as String?)
}
