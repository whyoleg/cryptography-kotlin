/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.konan.target.*

plugins {
    id("buildx-multiplatform-library")
    id("buildx-target-native-desktop")
    id("buildx-use-openssl")
}

description = "cryptography-kotlin OpenSSL3 provider (shared)"

kotlin {
    targets.configureEach {
        if (this !is KotlinNativeTarget) return@configureEach

        cinterop("linking", "common")

        if (this !is KotlinNativeTargetWithTests<*>) return@configureEach

        // on CI, Linux by default has openssl built with newer glibc
        // which cause errors trying to link it with current K/N toolchain
        if (konanTarget.family == Family.LINUX) testRuns.configureEach {
            executionSource.binary.linkTaskProvider.configure {
                dependsOn(openssl.prepareOpensslTaskProvider)
                binary.linkerOpts("-L${openssl.libDir(konanTarget).get().absolutePath}")
            }
        }
    }

    sourceSets {
        commonMain {
            dependencies {
                api(projects.cryptographyProviderOpenssl3Api)
            }
        }
        commonTest {
            dependencies {
                api(projects.cryptographyProviderOpenssl3Test)
            }
        }
    }
}

documentation {
    includes.set(null as String?)
}
