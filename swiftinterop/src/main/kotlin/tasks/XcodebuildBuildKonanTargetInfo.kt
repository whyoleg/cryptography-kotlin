/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.swiftinterop.tasks

import org.jetbrains.kotlin.konan.target.*

internal class XcodebuildBuildKonanTargetInfo(konanTarget: KonanTarget) {
    val target: XcodebuildBuildTarget.Generic
    val releaseFolder: String
    val arch: String

    init {
        when (konanTarget) {
            KonanTarget.MACOS_ARM64             -> {
                target = XcodebuildBuildTarget.Generic.MACOS
                releaseFolder = "Release"
                arch = "arm64"
            }
            KonanTarget.MACOS_X64               -> {
                target = XcodebuildBuildTarget.Generic.MACOS
                releaseFolder = "Release"
                arch = "x86_64"
            }
            KonanTarget.IOS_ARM64               -> {
                target = XcodebuildBuildTarget.Generic.IOS
                releaseFolder = "Release-iphoneos"
                arch = "arm64"
            }
            KonanTarget.IOS_SIMULATOR_ARM64     -> {
                target = XcodebuildBuildTarget.Generic.IOS_SIMULATOR
                releaseFolder = "Release-iphonesimulator"
                arch = "arm64"
            }
            KonanTarget.IOS_X64                 -> {
                target = XcodebuildBuildTarget.Generic.IOS_SIMULATOR
                releaseFolder = "Release-iphonesimulator"
                arch = "x86_64"
            }
            KonanTarget.TVOS_ARM64              -> {
                target = XcodebuildBuildTarget.Generic.TVOS
                releaseFolder = "Release-appletvos"
                arch = "arm64"
            }
            KonanTarget.TVOS_SIMULATOR_ARM64    -> {
                target = XcodebuildBuildTarget.Generic.TVOS_SIMULATOR
                releaseFolder = "Release-appletvsimulator"
                arch = "arm64"
            }
            KonanTarget.TVOS_X64                -> {
                target = XcodebuildBuildTarget.Generic.TVOS_SIMULATOR
                releaseFolder = "Release-appletvsimulator"
                arch = "x86_64"
            }
            KonanTarget.WATCHOS_ARM32           -> {
                target = XcodebuildBuildTarget.Generic.WATCHOS
                releaseFolder = "Release-watchos"
                arch = "armv7k"
            }
            KonanTarget.WATCHOS_ARM64           -> {
                target = XcodebuildBuildTarget.Generic.WATCHOS
                releaseFolder = "Release-watchos"
                arch = "arm64_32"
            }
            KonanTarget.WATCHOS_DEVICE_ARM64    -> {
                target = XcodebuildBuildTarget.Generic.WATCHOS
                releaseFolder = "Release-watchos"
                arch = "arm64"
            }
            KonanTarget.WATCHOS_SIMULATOR_ARM64 -> {
                target = XcodebuildBuildTarget.Generic.WATCHOS_SIMULATOR
                releaseFolder = "Release-watchsimulator"
                arch = "arm64"
            }
            KonanTarget.WATCHOS_X64             -> {
                target = XcodebuildBuildTarget.Generic.WATCHOS_SIMULATOR
                releaseFolder = "Release-watchsimulator"
                arch = "x86_64"
            }
            else                                -> error("Unsupported target: $konanTarget")
        }
    }
}
