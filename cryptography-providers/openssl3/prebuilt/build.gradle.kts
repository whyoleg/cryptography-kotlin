/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import ckbuild.openssl.*
import org.jetbrains.kotlin.gradle.*
import org.jetbrains.kotlin.gradle.plugin.*
import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.gradle.targets.native.tasks.*
import org.jetbrains.kotlin.gradle.tasks.*

plugins {
    id("ckbuild.multiplatform-library")
    id("ckbuild.multiplatform-provider-tests")
    id("ckbuild.use-openssl")
}

description = "cryptography-kotlin OpenSSL3 provider (prebuilt)"

@OptIn(ExperimentalKotlinGradlePluginApi::class)
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
            api(projects.cryptographyProviderOpenssl3Test)
        }
    }

    targets.withType<KotlinNativeTarget>().configureEach {
        cinterop("linking", "common")
    }

    // for mingw we link `zlib` statically, as on final-users Windows PCs, `zlib` is not installed by default,
    // while linking works fine (because K/N provides `zlib` inside it), running executable will fail.
    //
    // on other platforms `zlib` is pre-installed, so there are no such issues
    //
    // to properly test this on CI (where `zlib` is available),
    // we need to remove from PATH all paths that contain `zlib1.dll`.
    // we don't remove those paths from PATH automatically to not iterate over all files in PATH at configuration time.
    // instead, we do check if the new (adapted) PATH doesn't contain `zlib1.dll` at task execution time
    mingwX64 {
        testRuns.configureEach {
            @Suppress("UNCHECKED_CAST")
            (this as ExecutionTaskHolder<KotlinNativeTest>).executionTask.configure {
                // those values found experimentally on CI machines...
                val knownPathsWithZlibDll = setOf(
                    "C:\\Program Files\\Git\\mingw64\\bin",
                    "C:\\Program Files\\Microsoft Service Fabric\\bin\\Fabric\\Fabric.Code"
                )
                val currentPath = providers.environmentVariable("PATH").get()
                val paths = currentPath
                    .split(";")
                    .filter(String::isNotBlank)
                    .filter { it !in knownPathsWithZlibDll }
                val newPath = paths.joinToString(";")

                environment("PATH", newPath)
                doFirst {
                    val folders = paths.mapNotNull { folder ->
                        val hasZlib = File(folder).listFiles()?.any { it.name == "zlib1.dll" } == true
                        if (hasZlib) folder else null
                    }
                    if (folders.isNotEmpty()) {
                        error("Found `zlib1.dll` in paths: ${folders.joinToString("\n", "\n")}")
                    }
                }
            }
        }
    }
}

tasks.withType<CInteropProcess>().configureEach {
    uses(openssl.v3_5) {
        settings.extraOpts("-libraryPath", libDirectory(konanTarget).get().asFile.absolutePath)
    }
}

providerTests {
    packageName.set("dev.whyoleg.cryptography.providers.openssl3.prebuilt")
    imports.addAll("dev.whyoleg.cryptography.providers.openssl3.*")
    providerInitializers.put("OpenSSL3_Prebuilt", "CryptographyProvider.Openssl3")
}
