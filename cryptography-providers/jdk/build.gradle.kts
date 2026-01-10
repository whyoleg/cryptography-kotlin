/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import org.jetbrains.kotlin.gradle.*

plugins {
    id("ckbuild.multiplatform-library")
    id("ckbuild.multiplatform-provider-tests")
}

description = "cryptography-kotlin JDK provider"

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
            implementation(projects.cryptographyProviderBase)

            // should be used carefully, for specific cases
            compileOnly(libs.bouncycastle)
        }
    }
}

providerTests {
    packageName.set("dev.whyoleg.cryptography.providers.jdk")
    providerInitializers.put("JDK_Default", "CryptographyProvider.JDK")
}
