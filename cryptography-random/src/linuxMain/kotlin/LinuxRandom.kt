/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.random

import kotlinx.cinterop.*

internal abstract class LinuxRandom : PlatformRandom() {
    protected abstract fun fillBytes(pointer: CPointer<ByteVar>, size: Int): Int
    final override fun fillBytes(array: ByteArray) {
        val size = array.size
        array.usePinned {
            var filled = 0
            while (filled < size) {
                val chunkSize = fillBytes(it.addressOf(filled), size - filled)
                if (chunkSize < 0) errnoCheck()
                filled += chunkSize
            }
        }
    }
}
