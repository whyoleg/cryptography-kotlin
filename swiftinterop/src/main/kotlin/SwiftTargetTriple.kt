/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.swiftinterop

import org.jetbrains.kotlin.konan.target.*
import java.io.*

@Suppress("EnumEntryName")
enum class SwiftSdk(
    val sdk: String,
    val platform: String,
    val isSimulator: Boolean,
) : Serializable {
    macosx("macosx", "macos", false),

    iphoneos("iphoneos", "ios", false),
    iphonesimulator("iphonesimulator", "ios", true),

    watchos("watchos", "watchos", false),
    watchsimulator("watchsimulator", "watchos", true),

    appletvos("appletvos", "tvos", false),
    appletvsimulator("appletvsimulator", "tvos", true);
}

enum class SwiftTargetTriple(
    val arch: String,
    val sdk: SwiftSdk,
    val konanTarget: KonanTarget,
) : Serializable {
    MACOS_ARM64("arm64", SwiftSdk.macosx, KonanTarget.MACOS_ARM64),
    MACOS_X64("x86_64", SwiftSdk.macosx, KonanTarget.MACOS_X64),

    IOS_ARM64("arm64", SwiftSdk.iphoneos, KonanTarget.IOS_ARM64),
    IOS_SIMULATOR_ARM64("arm64", SwiftSdk.iphonesimulator, KonanTarget.IOS_SIMULATOR_ARM64),
    IOS_SIMULATOR_X64("x86_64", SwiftSdk.iphonesimulator, KonanTarget.IOS_X64),

    TVOS_ARM64("arm64", SwiftSdk.appletvos, KonanTarget.TVOS_ARM64),
    TVOS_SIMULATOR_ARM64("arm64", SwiftSdk.appletvsimulator, KonanTarget.TVOS_SIMULATOR_ARM64),
    TVOS_SIMULATOR_X64("x86_64", SwiftSdk.appletvsimulator, KonanTarget.TVOS_X64),

    WATCHOS_ARM64_32("arm64_32", SwiftSdk.watchos, KonanTarget.WATCHOS_ARM64),
    WATCHOS_ARM64("arm64", SwiftSdk.watchos, KonanTarget.WATCHOS_DEVICE_ARM64),
    WATCHOS_SIMULATOR_ARM64("arm64", SwiftSdk.watchsimulator, KonanTarget.WATCHOS_SIMULATOR_ARM64),
    WATCHOS_SIMULATOR_X64("x86_64", SwiftSdk.watchsimulator, KonanTarget.WATCHOS_X64);

    override fun toString(): String = when (sdk.isSimulator) {
        true  -> "$arch-apple-${sdk.platform}-simulator"
        false -> "$arch-apple-${sdk.platform}"
    }

    companion object {
        fun from(konanTarget: KonanTarget): SwiftTargetTriple =
            entries.find { it.konanTarget == konanTarget } ?: error("Unsupported target: $konanTarget")
    }
}
