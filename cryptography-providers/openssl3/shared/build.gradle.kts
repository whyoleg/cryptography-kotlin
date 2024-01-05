/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import ckbuild.*
import ckbuild.openssl.*
import org.jetbrains.kotlin.gradle.*
import org.jetbrains.kotlin.gradle.plugin.*
import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.gradle.targets.native.tasks.*
import org.jetbrains.kotlin.konan.target.*

plugins {
    id("ckbuild.multiplatform-library")
    id("ckbuild.use-openssl")
    id("ckbuild.multiplatform-provider-tests")
}

description = "cryptography-kotlin OpenSSL3 provider (shared)"

@OptIn(ExperimentalKotlinGradlePluginApi::class)
kotlin {
    desktopTargets()

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

    // We add prebuilt openssl to the library search path in 2 cases:
    // 1. For Linux, runners on CI by default have openssl built with newer glibc,
    // which causes errors trying to link it with the current K / N toolchain
    // 2. When target and host differ (cross-compiling)
    targets.withType<KotlinNativeTarget>().matching {
        it.konanTarget.family == Family.LINUX || it.konanTarget != HostManager.host
    }.configureEach {
        binaries.configureEach {
            linkerOpts("-L${openssl.v3_0.libDirectory(konanTarget).get().asFile.absolutePath}")
            linkTaskProvider.configure { dependsOn(openssl.v3_0.setupTask) }
        }
    }

    targets.withType<KotlinNativeTargetWithTests<*>>().configureEach {
        fun createTestRuns(classifier: String, extension: OpensslXExtension) {
            fun createTestRun(name: String, buildType: NativeBuildType) {
                testRuns.create(name) {
                    setExecutionSourceFrom(binaries.getTest(buildType))
                    @Suppress("UNCHECKED_CAST")
                    (this as ExecutionTaskHolder<KotlinNativeTest>).executionTask.configure {
                        val providerTestsStep = providers.gradleProperty("ckbuild.providerTests.step").orNull
                        onlyIf { providerTestsStep == null }
                        dependsOn(extension.setupTask)
                        when (konanTarget.family) {
                            Family.OSX   -> environment("DYLD_LIBRARY_PATH", extension.libDirectory(konanTarget).get().asFile.absolutePath)
                            Family.LINUX -> environment("LD_LIBRARY_PATH", extension.libDirectory(konanTarget).get().asFile.absolutePath)
                            Family.MINGW -> {
                                val opensslBinPath = extension.binDirectory("windows-x64").get().asFile.absolutePath
                                val currentPath = providers.environmentVariable("PATH").get()
                                environment("PATH", "$opensslBinPath;$currentPath")
                            }
                            else         -> error("not supported: $konanTarget")
                        }
                    }
                }
            }
            createTestRun("_${classifier}_Test", NativeBuildType.DEBUG)
            createTestRun("release_${classifier}_Test", NativeBuildType.RELEASE)
        }

        createTestRuns("3_0", openssl.v3_0)
        createTestRuns("3_1", openssl.v3_1)
        createTestRuns("3_2", openssl.v3_2)
    }
}

documentation {
    includes.set(null as String?)
}

providerTests {
    packageName.set("dev.whyoleg.cryptography.providers.openssl3.shared")
    imports.addAll("dev.whyoleg.cryptography.providers.openssl3.*")
    providerInitializers.put("OpenSSL3_Shared", "CryptographyProvider.Openssl3")
}
