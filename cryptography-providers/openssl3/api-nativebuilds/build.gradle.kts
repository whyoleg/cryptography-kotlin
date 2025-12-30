/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import com.ensody.nativebuilds.*

plugins {
    id("ckbuild.multiplatform-library")
    alias(libs.plugins.nativebuilds)
}

description = "cryptography-kotlin OpenSSL3 provider (API) based on NativeBuilds"

kotlin {
    nativeTargets()

    compilerOptions {
        optIn.addAll(
            OptIns.DelicateCryptographyApi,
            OptIns.CryptographyProviderApi,

            OptIns.ExperimentalForeignApi,
        )
    }

    sourceSets.commonMain {
        dependencies {
            api(projects.cryptographyCore)
            implementation(projects.cryptographyProviderBase)
        }

        kotlin {
            srcDir(file("../api-common"))
        }
    }

    cinterops(libs.nativebuilds.openssl.headers) {
        definitionFile.set(file("src/commonMain/cinterop/declarations.def"))
    }
}
