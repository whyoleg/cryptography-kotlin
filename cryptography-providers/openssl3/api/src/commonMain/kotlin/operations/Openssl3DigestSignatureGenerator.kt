/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.operations

import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.base.operations.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*
import platform.posix.*
import kotlin.experimental.*

internal abstract class Openssl3DigestSignatureGenerator(
    private val privateKey: CPointer<EVP_PKEY>,
    private val hashAlgorithm: String?,
) : SignatureGenerator {
    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = privateKey.upRef().cleaner()

    protected abstract fun MemScope.createParams(): CValuesRef<OSSL_PARAM>?

    // in case of no digest, streaming is not supported
    override fun createSignFunction(): SignFunction = if (hashAlgorithm == null) {
        AccumulatingSignFunction(::sign)
    } else {
        Openssl3DigestSignFunction(Resource(checkError(EVP_MD_CTX_new()), ::EVP_MD_CTX_free))
    }

    // one shot
    @OptIn(UnsafeNumber::class)
    private fun sign(data: ByteArray): ByteArray = memScoped {
        val context = checkError(EVP_MD_CTX_new())
        try {
            init(context)

            data.usePinned {
                val siglen = alloc<size_tVar>()
                checkError(EVP_DigestSign(context, null, siglen.ptr, it.safeAddressOfU(0), data.size.convert()))
                val signature = ByteArray(siglen.value.convert())
                checkError(EVP_DigestSign(context, signature.refToU(0), siglen.ptr, it.safeAddressOfU(0), data.size.convert()))
                signature.ensureSizeExactly(siglen.value.convert())
            }
        } finally {
            EVP_MD_CTX_free(context)
        }
    }

    private fun MemScope.init(context: CPointer<EVP_MD_CTX>) {
        checkError(
            EVP_DigestSignInit_ex(
                ctx = context,
                pctx = null,
                mdname = hashAlgorithm,
                libctx = null,
                props = null,
                pkey = privateKey,
                params = createParams()
            )
        )
    }

    // inner class to have a reference to class with cleaner
    private inner class Openssl3DigestSignFunction(
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
            signature.copyInto(destination, destinationOffset)
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
            init(context.access())
        }
    }
}
