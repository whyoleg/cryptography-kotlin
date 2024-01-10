/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.random

import kotlinx.cinterop.*
import platform.posix.*

internal fun createGetRandom(): CryptographyRandom? = if (getRandomAvailable()) GetRandom else null

private object GetRandom : LinuxRandom() {
    @OptIn(ExperimentalForeignApi::class, UnsafeNumber::class)
    override fun fillBytes(pointer: CPointer<ByteVar>, size: Int): Int = getrandom(pointer, size.convert(), 0.convert())
}

// https://docs.piston.rs/dev_menu/libc/constant.SYS_getrandom.html
private const val SYS_getrandom = 318

// https://docs.piston.rs/dev_menu/libc/constant.GRND_NONBLOCK.html
private const val GRND_NONBLOCK = 0x0001

private fun getRandomAvailable(): Boolean {
    val stubArray = ByteArray(1)
    val stubSize = stubArray.size

    @OptIn(ExperimentalForeignApi::class, UnsafeNumber::class)
    stubArray.usePinned {
        if (getrandom(it.addressOf(0), stubSize.convert(), GRND_NONBLOCK.convert()) >= 0) return true
    }

    return when (errno) {
        ENOSYS, EPERM -> false
        else          -> true
    }
}

@OptIn(ExperimentalForeignApi::class, UnsafeNumber::class)
private fun getrandom(out: CPointer<ByteVar>?, outSize: size_t, flags: UInt): Int =
    syscall(SYS_getrandom.convert(), out, outSize, flags).convert()
