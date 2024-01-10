/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.random

internal abstract class AbstractRandom : CryptographyRandom() {
    final override fun nextBits(bitCount: Int): Int {
        val numBytes = (bitCount + 7) / 8
        val b = nextBytes(numBytes)

        var next = 0
        for (i in 0 until numBytes) {
            next = (next shl 8) + (b[i].toInt() and 0xFF)
        }
        return next ushr numBytes * 8 - bitCount
    }

    //we can also implement nextBytes(array, index, index)
    final override fun nextBytes(array: ByteArray): ByteArray {
        if (array.isNotEmpty()) fillBytes(array)
        return array
    }

    protected abstract fun fillBytes(array: ByteArray)
}
