/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.random

import dev.whyoleg.cryptography.random.internal.cinterop.*
import kotlinx.cinterop.*
import platform.posix.*

internal fun createGetRandom(): CryptographyRandom? = if (getRandomAvailable()) GetRandom else null

private object GetRandom : LinuxRandom() {
    @OptIn(ExperimentalForeignApi::class, UnsafeNumber::class)
    override fun fillBytes(pointer: CPointer<ByteVar>, size: Int): Int = getrandom(pointer, size.convert(), 0.convert())
}

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

// TODO: SYS_getrandom=318 - not available in android native
// https://docs.piston.rs/dev_menu/libc/constant.SYS_getrandom.html
@OptIn(ExperimentalForeignApi::class, UnsafeNumber::class)
private fun getrandom(out: CPointer<ByteVar>?, outSize: size_t, flags: UInt): Int =
    syscall(/*SYS_getrandom*/318.convert(), out, outSize, flags).convert()
