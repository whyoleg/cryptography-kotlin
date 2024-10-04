/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.base.operations

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.providers.base.*

@CryptographyProviderApi
public class AccumulatingCipherFunction(
    private val finalize: (ByteArray) -> ByteArray,
) : BaseCipherFunction() {
    private var isClosed = false
    private var accumulator = EmptyByteArray

    override fun close() {
        isClosed = true
        accumulator = EmptyByteArray
    }

    private fun ensureNotClosed() {
        check(!isClosed) { "Already closed" }
    }

    private fun accumulate(source: ByteArray, startIndex: Int, endIndex: Int) {
        ensureNotClosed()
        checkBounds(source.size, startIndex, endIndex)
        accumulator += source.copyOfRange(startIndex, endIndex)
    }

    override val blockSize: Int get() = 0
    override fun maxOutputSize(inputSize: Int): Int = -1
    override fun maxInputSize(initialMaxInputSize: Int, expectedMaxOutputSize: Int): Int = Int.MAX_VALUE

    override fun transformToByteArray(source: ByteArray, startIndex: Int, endIndex: Int): ByteArray {
        accumulate(source, startIndex, endIndex)
        return EmptyByteArray
    }

    override fun transformIntoByteArray(
        source: ByteArray,
        destination: ByteArray,
        destinationOffset: Int,
        startIndex: Int,
        endIndex: Int,
    ): Int {
        accumulate(source, startIndex, endIndex)
        return 0
    }

    override fun finalizeToByteArray(): ByteArray {
        ensureNotClosed()
        return finalize(accumulator)
    }

    override fun finalizeIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
        val result = finalizeToByteArray()
        result.copyInto(destination, destinationOffset)
        return result.size
    }

    override fun transformAndFinalizeToByteArray(source: ByteArray, startIndex: Int, endIndex: Int): ByteArray {
        accumulate(source, startIndex, endIndex)
        return finalizeToByteArray()
    }

    override fun transformAndFinalizeIntoByteArray(
        source: ByteArray,
        destination: ByteArray,
        destinationOffset: Int,
        startIndex: Int,
        endIndex: Int,
    ): Int {
        accumulate(source, startIndex, endIndex)
        return finalizeIntoByteArray(destination, destinationOffset)
    }
}
