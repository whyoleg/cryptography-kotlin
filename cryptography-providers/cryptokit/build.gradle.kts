/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import dev.whyoleg.swiftinterop.*
import org.jetbrains.kotlin.gradle.plugin.mpp.*

plugins {
    id("ckbuild.multiplatform-library")
    id("ckbuild.multiplatform-provider-tests")
    id("dev.whyoleg.swiftinterop")
}

description = "cryptography-kotlin Cryptokit provider"

kotlin {
    appleTargets(
        supportsWatchosArm32 = false,
    )

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
        swiftInterop("DwcCryptoKitInterop") {
            packageName("dev.whyoleg.cryptography.providers.cryptokit.internal.swiftinterop")
            // TODO: migrate to new package and rename Swift classes to Dwc*
            // packageName("dev.whyoleg.cryptography.providers.cryptokit.internal.swift.DwcCryptoKitInterop")
        }
    }
}

providerTests {
    packageName.set("dev.whyoleg.cryptography.providers.cryptokit")
    providerInitializers.put("CryptoKit", "CryptographyProvider.CryptoKit")
}
