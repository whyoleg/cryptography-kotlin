/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import org.jetbrains.kotlin.gradle.*

plugins {
    id("ckbuild.multiplatform-library")
    id("ckbuild.multiplatform-provider-tests")
}

description = "cryptography-kotlin BouncyCastle provider"

@OptIn(ExperimentalKotlinGradlePluginApi::class)
kotlin {
    jvmTarget()

    compilerOptions {
        optIn.addAll(
            OptIns.DelicateCryptographyApi,
            OptIns.CryptographyProviderApi,
        )
    }

    sourceSets {
        jvmMain.dependencies {
            api(projects.cryptographyCore)
            implementation(libs.bouncycastle)
            // implementation(projects.cryptographyProviderBase)
        }
    }
}

providerTests {
    packageName.set("dev.whyoleg.cryptography.providers.bouncycastle")
    providerInitializers.put("BouncyCastle", "CryptographyProvider.BouncyCastle")
}
