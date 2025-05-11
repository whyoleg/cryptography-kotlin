/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*

plugins {

    id("ckbuild.multiplatform-library")
    id("ckbuild.multiplatform-provider-tests")
    id("dev.whyoleg.swiftinterop")
}

description = "cryptography-kotlin Cryptokit provider"

swiftInterop {
    packageName = "dev.whyoleg.cryptography.providers.cryptokit.internal.swiftinterop"
    iosVersion = "14"
    macosVersion = "11"
    tvosVersion = "14"
    watchosVersion = "7"
}

kotlin {
    appleTargets()

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
}

providerTests {
    packageName.set("dev.whyoleg.cryptography.providers.cryptokit")
    providerInitializers.put("CryptoKit", "CryptographyProvider.CryptoKit")
}
