/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import org.jetbrains.kotlin.gradle.*

plugins {
    id("ckbuild.multiplatform-library")
    id("ckbuild.multiplatform-provider-tests")
}

description = "cryptography-kotlin Apple provider"

@OptIn(ExperimentalKotlinGradlePluginApi::class)
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
    packageName.set("dev.whyoleg.cryptography.providers.apple")
    providerInitializers.put("Apple", "CryptographyProvider.Apple")
}
