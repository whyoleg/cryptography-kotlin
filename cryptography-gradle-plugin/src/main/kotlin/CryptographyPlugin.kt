/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.gradle

import org.gradle.api.*
import org.gradle.api.provider.*
import org.gradle.process.*
import org.jetbrains.kotlin.gradle.dsl.*
import org.jetbrains.kotlin.gradle.plugin.mpp.*
import org.jetbrains.kotlin.konan.target.*
import java.io.*
import javax.inject.*

/**
 * Configuration for the `dev.whyoleg.cryptography` plugin.
 */
public abstract class CryptographyExtension {
    /**
     * When `true`, the plugin automatically adds Swift library linker options (`-L`) for every
     * Apple target binary, resolving the active Xcode installation dynamically via `xcrun`.
     *
     * Enable this when using the CryptoKit provider with Xcode installed in a non-default location.
     *
     * Defaults to `false`.
     */
    public abstract val configureSwiftLinkerOpts: Property<Boolean>
}

public abstract class CryptographyPlugin : Plugin<Project> {
    override fun apply(target: Project) {
        val ckext = target.extensions.create("cryptography", CryptographyExtension::class.java).apply {
            configureSwiftLinkerOpts.convention(false)
        }
        val xcodeSwiftLibsPath = target.providers.of(XcodeSwiftPath::class.java) {}.map {
            // it's only possible to get path to swift binary, not libs
            it.replace("/usr/bin/swift", "/usr/lib/swift")
        }

        target.afterEvaluate {
            target.plugins.withId("org.jetbrains.kotlin.multiplatform") {
                target.extensions.configure<KotlinMultiplatformExtension>("kotlin") { kotlinExtension ->
                    kotlinExtension.targets.configureEach { target ->
                        if (target is KotlinNativeTarget && target.konanTarget.family.isAppleFamily) {
                            val opts = xcodeSwiftLibsPath.map { libsDir ->
                                val platformDir = when (target.konanTarget) {
                                    KonanTarget.IOS_ARM64               -> "iphoneos"
                                    KonanTarget.IOS_SIMULATOR_ARM64     -> "iphonesimulator"
                                    KonanTarget.IOS_X64                 -> "iphonesimulator"

                                    KonanTarget.MACOS_ARM64             -> "macosx"
                                    KonanTarget.MACOS_X64               -> "macosx"

                                    KonanTarget.TVOS_ARM64              -> "appletvos"
                                    KonanTarget.TVOS_SIMULATOR_ARM64    -> "appletvsimulator"
                                    KonanTarget.TVOS_X64                -> "appletvsimulator"

                                    KonanTarget.WATCHOS_ARM32           -> "watchos"
                                    KonanTarget.WATCHOS_ARM64           -> "watchos"
                                    KonanTarget.WATCHOS_DEVICE_ARM64    -> "watchos"
                                    KonanTarget.WATCHOS_SIMULATOR_ARM64 -> "watchsimulator"
                                    KonanTarget.WATCHOS_X64             -> "watchsimulator"
                                    else                                -> error("Unsupported target: ${target.konanTarget}")
                                }
                                "-L$libsDir/$platformDir"
                            }
                            target.binaries.configureEach { binary ->
                                if (ckext.configureSwiftLinkerOpts.get()) binary.linkerOpts(opts.get())
                            }
                        }
                    }
                }
            }
        }
    }
}

private abstract class XcodeSwiftPath @Inject constructor(
    private val exec: ExecOperations,
) : ValueSource<String, ValueSourceParameters.None> {
    override fun obtain(): String? {
        val bytes = ByteArrayOutputStream()
        exec.exec {
            it.standardOutput = bytes
            it.commandLine("xcrun", "--find", "swift")
        }.assertNormalExitValue().rethrowFailure()
        return bytes.toString().substringBefore("\n") // take the first line
    }
}
