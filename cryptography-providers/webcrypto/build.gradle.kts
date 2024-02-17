/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import org.jetbrains.kotlin.gradle.*

plugins {
    id("ckbuild.multiplatform-library")
    id("ckbuild.multiplatform-provider-tests")
}

description = "cryptography-kotlin WebCrypto provider"

@OptIn(ExperimentalKotlinGradlePluginApi::class)
kotlin {
    jsTarget()
    wasmJsTarget()

    compilerOptions {
        optIn.addAll(
            OptIns.InsecureAlgorithm,
            OptIns.CryptographyProviderApi,
        )
        freeCompilerArgs.add("-Xexpect-actual-classes")
    }

    sourceSets.commonMain.dependencies {
        api(projects.cryptographyCore)
        implementation(projects.cryptographySerializationPem)
        implementation(projects.cryptographySerializationAsn1)
        implementation(projects.cryptographySerializationAsn1Modules)
    }
}

providerTests {
    packageName.set("dev.whyoleg.cryptography.providers.webcrypto")
    providerInitializers.put("WebCrypto", "CryptographyProvider.WebCrypto")
}
