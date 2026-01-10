/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.base.operations

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*

@CryptographyProviderApi
public class AccumulatingVerifyFunction(
    private val verify: (data: ByteArray, signature: ByteArray) -> String?,
) : VerifyFunction {
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

    override fun tryVerify(signature: ByteArray, startIndex: Int, endIndex: Int): Boolean {
        return verifyError(signature, startIndex, endIndex) == null
    }

    override fun verify(signature: ByteArray, startIndex: Int, endIndex: Int) {
        val error = verifyError(signature, startIndex, endIndex) ?: return
        error("Invalid signature: $error")
    }

    private fun verifyError(signature: ByteArray, startIndex: Int, endIndex: Int): String? {
        ensureNotClosed()
        checkBounds(signature.size, startIndex, endIndex)
        return verify(accumulator, signature.copyOfRange(startIndex, endIndex)).also {
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
