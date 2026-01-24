/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.base.operations

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*

@CryptographyProviderApi
public class AccumulatingSignFunction(
    private val sign: (ByteArray) -> ByteArray,
) : SignFunction {
    private var isClosed = false
    private var accumulator = EmptyByteArray

    private fun ensureNotClosed() {
        check(!isClosed) { "Already closed" }
    }

    override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
        ensureNotClosed()
        checkBounds(source.size, startIndex, endIndex)

        accumulator += source.copyOfRange(startIndex, endIndex)
    }

    override fun signIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
        val signature = signToByteArray()
        checkBounds(destination.size, destinationOffset, destinationOffset + signature.size)
        signature.copyInto(destination, destinationOffset)
        return signature.size
    }

    override fun signToByteArray(): ByteArray {
        ensureNotClosed()
        return sign(accumulator).also {
            reset()
        }
    }

    override fun reset() {
        ensureNotClosed()
        accumulator = EmptyByteArray
    }

    override fun close() {
        isClosed = true
        accumulator = EmptyByteArray
    }
}
