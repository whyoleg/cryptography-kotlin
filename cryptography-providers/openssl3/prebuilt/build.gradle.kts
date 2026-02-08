/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import ckbuild.openssl.*
import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.gradle.tasks.*

plugins {
    id("ckbuild.multiplatform-library")
    id("ckbuild.multiplatform-provider-tests")
    id("ckbuild.use-openssl")
}

description = "cryptography-kotlin OpenSSL3 provider (prebuilt)"

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
        }
        commonTest.dependencies {
            implementation(projects.cryptographyProviderOpenssl3Test)
        }
    }

    targets.withType<KotlinNativeTarget>().configureEach {
        cinterop("linking", "common")
    }
}

tasks.withType<CInteropProcess>().configureEach {
    uses(openssl.v3_6) {
        settings.extraOpts("-libraryPath", libDirectory(konanTarget).get().asFile.absolutePath)
    }
}

providerTests {
    packageName.set("dev.whyoleg.cryptography.providers.openssl3.prebuilt")
    imports.addAll("dev.whyoleg.cryptography.providers.openssl3.*")
    providerInitializers.put("OpenSSL3_Prebuilt", "CryptographyProvider.Openssl3")
}
