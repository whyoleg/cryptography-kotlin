/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import org.jetbrains.kotlin.gradle.*
import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.konan.target.*

plugins {
    id("ckbuild.multiplatform-library")
    id("ckbuild.use-openssl")
}

description = "cryptography-kotlin OpenSSL3 provider (shared)"

@OptIn(ExperimentalKotlinGradlePluginApi::class)
kotlin {
    desktopTargets()

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

    // We add prebuilt openssl to the library search path in 2 cases:
    // 1. For Linux, runners on CI by default have openssl built with newer glibc,
    // which causes errors trying to link it with the current K / N toolchain
    // 2. When target and host differ, and there is no compatible openssl in default paths
    targets.withType<KotlinNativeTarget>().matching {
        it.konanTarget.family == Family.LINUX || it.konanTarget != HostManager.host
    }.configureEach {
        binaries.configureEach {
            linkTaskProvider.configure {
                dependsOn(tasks.setupOpenssl3)
                binary.linkerOpts("-L${openssl3.libDirectory(konanTarget).get().asFile.absolutePath}")
            }
        }
    }
}

documentation {
    includes.set(null as String?)
}
