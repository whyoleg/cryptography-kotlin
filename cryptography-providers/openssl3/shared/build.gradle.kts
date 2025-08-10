/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import ckbuild.openssl.*
import org.jetbrains.kotlin.gradle.*
import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.konan.target.*

plugins {
    id("ckbuild.multiplatform-library")
    id("ckbuild.multiplatform-provider-tests")
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
    // 2. When target and host differ (cross-compiling)
    targets.withType<KotlinNativeTarget>().matching {
        it.konanTarget.family == Family.LINUX || it.konanTarget != HostManager.host
    }.configureEach {
        binaries.configureEach {
            linkerOpts("-L${openssl.v3_0.libDirectory(konanTarget).get().asFile.absolutePath}")
            linkTaskProvider.configure { uses(openssl.v3_0) }
        }
    }
}

providerTests {
    packageName.set("dev.whyoleg.cryptography.providers.openssl3.shared")
    imports.addAll("dev.whyoleg.cryptography.providers.openssl3.*")
    providerInitializers.put("OpenSSL3_Shared", "CryptographyProvider.Openssl3")
}
