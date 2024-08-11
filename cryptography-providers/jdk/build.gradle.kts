/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import org.jetbrains.kotlin.gradle.*

plugins {
    id("ckbuild.multiplatform-library")
    id("ckbuild.multiplatform-sweetspi")
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
        }
        jvmTest.dependencies {
            implementation(libs.bouncycastle)
        }
    }
}

providerTests {
    packageName.set("dev.whyoleg.cryptography.providers.jdk")
    imports.addAll("org.bouncycastle.jce.provider.*")
    providerInitializers.put("JDK", "CryptographyProvider.JDK")
    providerInitializers.put("JDK_BC", "CryptographyProvider.JDK(BouncyCastleProvider())")
}
