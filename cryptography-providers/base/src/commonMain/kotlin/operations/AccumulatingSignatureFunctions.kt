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
    private var closed = false
    private val chunks = ArrayList<ByteArray>(4)

    private fun ensureOpen() { check(!closed) { "Already closed" } }

    override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
        ensureOpen()
        checkBounds(source.size, startIndex, endIndex)
        if (startIndex == 0 && endIndex == source.size) chunks += source
        else chunks += source.copyOfRange(startIndex, endIndex)
    }

    override fun signIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
        val sig = signToByteArray()
        sig.copyInto(destination, destinationOffset)
        return sig.size
    }

    override fun signToByteArray(): ByteArray {
        ensureOpen()
        val total = chunks.sumOf { it.size }
        val data = ByteArray(total)
        var off = 0
        chunks.forEach { arr -> arr.copyInto(data, off); off += arr.size }
        val out = oneShot(data)
        reset()
        return out
    }

    override fun reset() {
        ensureOpen()
        chunks.clear()
    }

    override fun close() {
        closed = true
        chunks.clear()
    }
}

@CryptographyProviderApi
public class AccumulatingVerifyFunction(
    private val oneShot: (data: ByteArray, signature: ByteArray, startIndex: Int, endIndex: Int) -> Boolean,
) : VerifyFunction {
    private var closed = false
    private val chunks = ArrayList<ByteArray>(4)

    private fun ensureOpen() { check(!closed) { "Already closed" } }

    override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
        ensureOpen()
        checkBounds(source.size, startIndex, endIndex)
        if (startIndex == 0 && endIndex == source.size) chunks += source
        else chunks += source.copyOfRange(startIndex, endIndex)
    }

    override fun tryVerify(signature: ByteArray, startIndex: Int, endIndex: Int): Boolean {
        ensureOpen()
        checkBounds(signature.size, startIndex, endIndex)
        val total = chunks.sumOf { it.size }
        val data = ByteArray(total)
        var off = 0
        chunks.forEach { arr -> arr.copyInto(data, off); off += arr.size }
        val ok = oneShot(data, signature, startIndex, endIndex)
        reset()
        return ok
    }

    override fun verify(signature: ByteArray, startIndex: Int, endIndex: Int) {
        check(tryVerify(signature, startIndex, endIndex)) { "Invalid signature" }
    }

    override fun reset() {
        ensureOpen()
        chunks.clear()
    }

    override fun close() {
        closed = true
        chunks.clear()
    }
}

