/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

plugins {
    id("ckbuild.multiplatform-base")
    id("ckbuild.multiplatform-android")
    id("ckbuild.multiplatform-provider-tests")
}

kotlin {
    sourceSets {
        androidInstrumentedTest.dependencies {
            implementation(projects.cryptographyProviderJdk)
        }
    }
}

providerTests {
    packageName.set("dev.whyoleg.cryptography.providers.jdk.android")
    imports.addAll("dev.whyoleg.cryptography.providers.jdk.*")
    providerInitializers.put("JDK_Android", "CryptographyProvider.JDK")
}
