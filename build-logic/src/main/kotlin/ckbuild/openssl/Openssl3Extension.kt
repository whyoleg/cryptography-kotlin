/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package ckbuild.openssl

import org.gradle.api.file.*
import org.gradle.api.provider.*
import org.jetbrains.kotlin.konan.target.*

abstract class Openssl3Extension(
    private val directory: Provider<Directory>,
) {
    fun libDirectory(target: KonanTarget): Provider<Directory> = libDirectory(target.opensslTarget())
    fun includeDirectory(target: KonanTarget): Provider<Directory> = includeDirectory(target.opensslTarget())

    private fun libDirectory(target: String) = directory.map { it.dir("$target/lib") }
    private fun includeDirectory(target: String) = directory.map { it.dir("$target/include") }
}


private fun KonanTarget.opensslTarget(): String = when (this) {
    KonanTarget.IOS_ARM64           -> "ios-device-arm64"
    KonanTarget.IOS_SIMULATOR_ARM64 -> "ios-simulator-arm64"
    KonanTarget.IOS_X64             -> "ios-simulator-x64"
    KonanTarget.LINUX_X64           -> "linux-x64"
    KonanTarget.MACOS_ARM64         -> "macos-arm64"
    KonanTarget.MACOS_X64           -> "macos-x64"
    KonanTarget.MINGW_X64           -> "mingw-x64"
    else                            -> TODO("NOT SUPPORTED")
}
