/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.gradle.tasks.*

plugins {
    id("buildx-multiplatform-library")
    id("buildx-target-native-all")
    id("buildx-use-openssl")
}

description = "cryptography-kotlin OpenSSL3 provider (prebuilt)"

tasks.withType<CInteropProcess>().configureEach {
    dependsOn(tasks.setupOpenssl3)
    settings.extraOpts("-libraryPath", openssl3.libDirectory(konanTarget).get().asFile.absolutePath)
}

kotlin {
    targets.withType<KotlinNativeTarget>().configureEach {
        cinterop("linking", "common")
    }

    sourceSets {
        commonMain {
            dependencies {
                api(projects.cryptographyProviderOpenssl3Api)
            }
        }
        commonTest {
            dependencies {
                api(projects.cryptographyProviderOpenssl3Test)
            }
        }
    }
}

documentation {
    includes.set(null as String?)
}
