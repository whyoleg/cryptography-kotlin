/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.operations

import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.base.operations.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*
import platform.posix.*

@OptIn(UnsafeNumber::class)
internal class EvpPKeyCipherFunction(
    private val key: CPointer<EVP_PKEY>,
    private val encrypt: Boolean,
    private val createParameters: MemScope.() -> CArrayPointer<OSSL_PARAM>?,
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

    private fun finalize(): ByteArray {
        ensureNotClosed()

        return memScoped {
            val context = checkError(EVP_PKEY_CTX_new_from_pkey(null, key, null))
            try {
                checkError(
                    EVP_PKEY_cipher_init_ex(
                        ctx = context,
                        params = createParameters()
                    )
                )

                accumulator.usePinned { inputPin ->
                    val outlen = alloc<size_tVar>()
                    checkError(
                        EVP_PKEY_cipher(
                            ctx = context,
                            out = null,
                            outlen = outlen.ptr,
                            `in` = inputPin.safeAddressOfU(0),
                            inlen = accumulator.size.convert()
                        )
                    )
                    val output = ByteArray(outlen.value.convert())
                    output.usePinned { outputPin ->
                        checkError(
                            EVP_PKEY_cipher(
                                ctx = context,
                                out = outputPin.safeAddressOfU(0),
                                outlen = outlen.ptr,
                                `in` = inputPin.safeAddressOfU(0),
                                inlen = accumulator.size.convert()
                            )
                        )
                    }
                    output.ensureSizeExactly(outlen.value.convert())
                }
            } finally {
                EVP_PKEY_CTX_free(context)
            }
        }
    }

    private fun EVP_PKEY_cipher(
        ctx: CPointer<EVP_PKEY_CTX>?,
        out: CPointer<UByteVar>?,
        outlen: CPointer<size_tVar>?,
        `in`: CPointer<UByteVar>?,
        inlen: size_t,
    ): Int = when {
        encrypt -> EVP_PKEY_encrypt(ctx, out, outlen, `in`, inlen)
        else    -> EVP_PKEY_decrypt(ctx, out, outlen, `in`, inlen)
    }

    private fun EVP_PKEY_cipher_init_ex(
        ctx: CPointer<EVP_PKEY_CTX>?,
        params: CArrayPointer<OSSL_PARAM>?,
    ): Int = when {
        encrypt -> EVP_PKEY_encrypt_init_ex(ctx, params)
        else    -> EVP_PKEY_decrypt_init_ex(ctx, params)
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
        return finalize()
    }

    override fun finalizeIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
        val result = finalize()
        result.copyInto(destination, destinationOffset)
        return result.size
    }

    override fun transformAndFinalizeToByteArray(source: ByteArray, startIndex: Int, endIndex: Int): ByteArray {
        accumulate(source, startIndex, endIndex)
        return finalize()
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
