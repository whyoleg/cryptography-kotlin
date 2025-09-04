/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.operations

import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*
import platform.posix.*
import kotlin.experimental.*

internal abstract class Openssl3DigestSignatureGenerator(
    private val privateKey: CPointer<EVP_PKEY>,
    // when null, performs one-shot signing (e.g., EdDSA)
    private val hashAlgorithm: String?,
) : SignatureGenerator {
    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = privateKey.upRef().cleaner()

    protected abstract fun MemScope.createParams(): CValuesRef<OSSL_PARAM>?

    override fun createSignFunction(): SignFunction = when (hashAlgorithm) {
        null -> OneShotSignFunction()
        else -> StreamingSignFunction(Resource(checkError(EVP_MD_CTX_new()), ::EVP_MD_CTX_free))
    }

    // inner class to have a reference to class with cleaner
    private inner class StreamingSignFunction(
        private val context: Resource<CPointer<EVP_MD_CTX>>,
    ) : SignFunction, SafeCloseable(SafeCloseAction(context, AutoCloseable::close)) {
        init {
            reset()
        }

        @OptIn(UnsafeNumber::class)
        override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
            checkBounds(source.size, startIndex, endIndex)

            val context = context.access()
            source.usePinned {
                checkError(EVP_DigestSignUpdate(context, it.safeAddressOf(startIndex), (endIndex - startIndex).convert()))
            }
        }

        override fun signIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
            val signature = signToByteArray()
            checkBounds(destination.size, destinationOffset, destinationOffset + signature.size)
            signature.copyInto(destination, destinationOffset, destinationOffset)
            return signature.size
        }

        @OptIn(UnsafeNumber::class)
        override fun signToByteArray(): ByteArray = memScoped {
            val context = context.access()
            val siglen = alloc<size_tVar>()
            checkError(EVP_DigestSignFinal(context, null, siglen.ptr))
            val signature = ByteArray(siglen.value.convert())
            checkError(EVP_DigestSignFinal(context, signature.refToU(0), siglen.ptr))
            signature.ensureSizeExactly(siglen.value.convert())
        }

        override fun reset(): Unit = memScoped {
            val context = context.access()
            checkError(
                EVP_DigestSignInit_ex(
                    ctx = context,
                    pctx = null,
                    mdname = hashAlgorithm!!,
                    libctx = null,
                    props = null,
                    pkey = privateKey,
                    params = createParams()
                )
            )
        }
    }

    private inner class OneShotSignFunction : SignFunction {
        private var isClosed = false
        private var accumulator = EmptyByteArray

        private fun ensureOpen() = check(!isClosed) { "Already closed" }

        override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
            ensureOpen()
            checkBounds(source.size, startIndex, endIndex)
            // accumulate until final
            accumulator += source.copyOfRange(startIndex, endIndex)
        }

        override fun signIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
            val sig = signToByteArray()
            checkBounds(destination.size, destinationOffset, destinationOffset + sig.size)
            sig.copyInto(destination, destinationOffset)
            return sig.size
        }

        @OptIn(UnsafeNumber::class)
        override fun signToByteArray(): ByteArray = memScoped {
            ensureOpen()
            val ctx = checkError(EVP_MD_CTX_new())
            try {
                checkError(
                    EVP_DigestSignInit_ex(
                        ctx = ctx,
                        pctx = null,
                        mdname = null, // one-shot mode
                        libctx = null,
                        props = null,
                        pkey = privateKey,
                        params = createParams()
                    )
                )

                val siglen = alloc<size_tVar>()
                accumulator.usePinned { pin ->
                    checkError(EVP_DigestSign(ctx, null, siglen.ptr, pin.safeAddressOfU(0), accumulator.size.convert()))
                    val out = ByteArray(siglen.value.convert())
                    out.usePinned { outPin ->
                        checkError(EVP_DigestSign(ctx, outPin.safeAddressOfU(0), siglen.ptr, pin.safeAddressOfU(0), accumulator.size.convert()))
                    }
                    out.ensureSizeExactly(siglen.value.convert())
                    out
                }
            } finally {
                EVP_MD_CTX_free(ctx)
                isClosed = true
            }
        }

        override fun reset() {
            isClosed = false
            accumulator = EmptyByteArray
        }

        override fun close() {
            isClosed = true
            accumulator = EmptyByteArray
        }
    }
}
