/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.random

import kotlinx.cinterop.*
import platform.posix.*
import kotlin.native.concurrent.*

internal fun createURandom(): CryptographyRandom {
    awaitURandomReady()
    return URandom
}

private object URandom : LinuxRandom() {
    @OptIn(ExperimentalForeignApi::class, UnsafeNumber::class)
    override fun fillBytes(pointer: CPointer<ByteVar>, size: Int): Int = read(FD.value, pointer, size.convert()).convert()
}

@ThreadLocal
private object FD {
    val value = open("/dev/urandom")
}

@OptIn(ExperimentalForeignApi::class)
private fun awaitURandomReady() {
    val randomFd = open("/dev/random")
    try {
        memScoped {
            val pollFd = alloc<pollfd> {
                fd = randomFd
                events = POLLIN.convert()
                revents = 0
            }

            while (true) {
                @OptIn(UnsafeNumber::class)
                if (poll(pollFd.ptr, 1.convert(), (-1).convert()) >= 0) break

                when (errno) {
                    EINTR, EAGAIN -> continue
                    else          -> errnoCheck()
                }
            }
        }
    } finally {
        close(randomFd)
    }
}

private fun open(path: String): Int {
    val fd = open(path, O_RDONLY, null)
    if (fd <= 0) errnoCheck()
    return fd
}
