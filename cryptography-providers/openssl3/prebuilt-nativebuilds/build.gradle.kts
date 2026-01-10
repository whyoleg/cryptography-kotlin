/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*

plugins {
    id("ckbuild.multiplatform-library")
    id("ckbuild.multiplatform-provider-tests")
    alias(libs.plugins.nativebuilds)
}

description = "cryptography-kotlin OpenSSL3 provider (prebuilt) based on NativeBuilds"

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
            api(libs.nativebuilds.openssl.libcrypto)
        }
        commonTest.dependencies {
            implementation(projects.cryptographyProviderOpenssl3Test)
        }
    }
}

providerTests {
    packageName.set("dev.whyoleg.cryptography.providers.openssl3.prebuiltnativebuilds")
    imports.addAll("dev.whyoleg.cryptography.providers.openssl3.*")
    providerInitializers.put("OpenSSL3_Prebuilt_NativeBuilds", "CryptographyProvider.Openssl3")
}
