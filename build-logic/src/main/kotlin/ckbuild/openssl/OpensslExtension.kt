/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package ckbuild.openssl

import org.gradle.api.*
import org.gradle.api.file.*
import org.gradle.api.provider.*
import org.gradle.api.services.*
import org.jetbrains.kotlin.konan.target.*

@Suppress("PropertyName")
abstract class OpensslService : BuildService<BuildServiceParameters.None> {
    abstract val v3_0: DirectoryProperty
    abstract val v3_6: DirectoryProperty
}

@Suppress("PropertyName")
class OpensslExtension(service: Provider<OpensslService>) {
    val v3_0: OpensslXExtension = OpensslXExtension(service.flatMap { it.v3_0 })
    val v3_6: OpensslXExtension = OpensslXExtension(service.flatMap { it.v3_6 })
}

fun Task.uses(openssl: OpensslXExtension, block: OpensslXExtension.() -> Unit = {}) {
    dependsOn(openssl.directory)
    block(openssl)
}

class OpensslXExtension(internal val directory: Provider<Directory>) {
    fun libDirectory(target: KonanTarget): Provider<Directory> = libDirectory(opensslTarget(target))
    fun includeDirectory(target: KonanTarget): Provider<Directory> = includeDirectory(opensslTarget(target))

    private fun libDirectory(target: String) = directory.map { it.dir("$target/lib") }
    private fun includeDirectory(target: String) = directory.map { it.dir("$target/include") }
    private fun opensslTarget(target: KonanTarget): String = when (target) {
        KonanTarget.IOS_ARM64               -> "ios-device-arm64"
        KonanTarget.IOS_SIMULATOR_ARM64     -> "ios-simulator-arm64"
        KonanTarget.IOS_X64                 -> "ios-simulator-x64"
        KonanTarget.TVOS_ARM64              -> "tvos-device-arm64"
        KonanTarget.TVOS_SIMULATOR_ARM64    -> "tvos-simulator-arm64"
        KonanTarget.WATCHOS_ARM64           -> "watchos-device-arm64_32"
        KonanTarget.WATCHOS_DEVICE_ARM64    -> "watchos-device-arm64"
        KonanTarget.WATCHOS_SIMULATOR_ARM64 -> "watchos-simulator-arm64"
        KonanTarget.LINUX_X64               -> "linux-x64"
        KonanTarget.LINUX_ARM64             -> "linux-arm64"
        KonanTarget.MACOS_ARM64             -> "macos-arm64"
        KonanTarget.MINGW_X64               -> "mingw-x64"
        else -> error("$target is not supported by OpenSSL")
    }
}
