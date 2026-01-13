/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.base.operations

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*

@CryptographyProviderApi
public class AccumulatingSignFunction(
    private val oneShot: (data: ByteArray) -> ByteArray,
) : SignFunction {
    private var isClosed = false
    private var accumulator = EmptyByteArray

    private fun ensureNotClosed() { check(!isClosed) { "Already closed" } }
    private fun accumulate(source: ByteArray, startIndex: Int, endIndex: Int) {
        ensureNotClosed()
        checkBounds(source.size, startIndex, endIndex)
        accumulator += source.copyOfRange(startIndex, endIndex)
    }

    override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
        accumulate(source, startIndex, endIndex)
    }

    override fun signIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
        val sig = signToByteArray()
        sig.copyInto(destination, destinationOffset)
        return sig.size
    }

    override fun signToByteArray(): ByteArray {
        ensureNotClosed()
        val out = oneShot(accumulator)
        reset()
        return out
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

@CryptographyProviderApi
public class AccumulatingVerifyFunction(
    private val oneShot: (data: ByteArray, signature: ByteArray, startIndex: Int, endIndex: Int) -> Boolean,
) : VerifyFunction {
    private var isClosed = false
    private var accumulator = EmptyByteArray

    private fun ensureNotClosed() { check(!isClosed) { "Already closed" } }
    private fun accumulate(source: ByteArray, startIndex: Int, endIndex: Int) {
        ensureNotClosed()
        checkBounds(source.size, startIndex, endIndex)
        accumulator += source.copyOfRange(startIndex, endIndex)
    }

    override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
        accumulate(source, startIndex, endIndex)
    }

    override fun tryVerify(signature: ByteArray, startIndex: Int, endIndex: Int): Boolean {
        ensureNotClosed()
        checkBounds(signature.size, startIndex, endIndex)
        val ok = oneShot(accumulator, signature, startIndex, endIndex)
        reset()
        return ok
    }

    override fun verify(signature: ByteArray, startIndex: Int, endIndex: Int) {
        check(tryVerify(signature, startIndex, endIndex)) { "Invalid signature" }
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
