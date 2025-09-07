/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.operations

import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.base.operations.*
import kotlinx.cinterop.*
import kotlin.experimental.*

internal abstract class Openssl3DigestSignatureVerifier(
    private val publicKey: CPointer<EVP_PKEY>,
    // when null, performs one-shot verification (e.g., EdDSA)
    private val hashAlgorithm: String?,
) : SignatureVerifier {
    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = publicKey.upRef().cleaner()

    protected abstract fun MemScope.createParams(): CValuesRef<OSSL_PARAM>?

    override fun createVerifyFunction(): VerifyFunction = when (hashAlgorithm) {
        null -> AccumulatingVerifyFunction { data, signature, startIndex, endIndex ->
            memScoped {
                val ctx = checkError(EVP_MD_CTX_new())
                try {
                    checkError(
                        EVP_DigestVerifyInit_ex(
                            ctx = ctx,
                            pctx = null,
                            mdname = null, // one-shot mode
                            libctx = null,
                            props = null,
                            pkey = publicKey,
                            params = createParams()
                        )
                    )
                    val result = signature.usePinned { sigPin ->
                        data.usePinned { dataPin ->
                            EVP_DigestVerify(
                                ctx,
                                sigPin.safeAddressOfU(startIndex),
                                (endIndex - startIndex).convert(),
                                dataPin.safeAddressOfU(0),
                                data.size.convert()
                            )
                        }
                    }
                    if (result != 0) checkError(result)
                    result == 1
                } finally {
                    EVP_MD_CTX_free(ctx)
                }
            }
        }
        else -> StreamingVerifyFunction(Resource(checkError(EVP_MD_CTX_new()), ::EVP_MD_CTX_free))
    }

    // inner class to have a reference to class with cleaner
    private inner class StreamingVerifyFunction(
        private val context: Resource<CPointer<EVP_MD_CTX>>,
    ) : VerifyFunction, SafeCloseable(SafeCloseAction(context, AutoCloseable::close)) {
        init {
            reset()
        }

        @OptIn(UnsafeNumber::class)
        override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
            checkBounds(source.size, startIndex, endIndex)

            val context = context.access()
            source.usePinned {
                checkError(EVP_DigestVerifyUpdate(context, it.safeAddressOf(startIndex), (endIndex - startIndex).convert()))
            }
        }

        @OptIn(UnsafeNumber::class)
        override fun tryVerify(signature: ByteArray, startIndex: Int, endIndex: Int): Boolean {
            checkBounds(signature.size, startIndex, endIndex)

            val context = context.access()
            val result = signature.usePinned {
                EVP_DigestVerifyFinal(context, it.safeAddressOfU(startIndex), (endIndex - startIndex).convert())
            }
            // 0     - means verification failed
            // 1     - means verification succeeded
            // other - means error
            if (result != 0) checkError(result)
            return result == 1
        }

        override fun verify(signature: ByteArray, startIndex: Int, endIndex: Int) {
            check(tryVerify(signature, startIndex, endIndex)) { "Invalid signature" }
        }

        override fun reset(): Unit = memScoped {
            val context = context.access()
            checkError(
                EVP_DigestVerifyInit_ex(
                    ctx = context,
                    pctx = null,
                    mdname = hashAlgorithm!!,
                    libctx = null,
                    props = null,
                    pkey = publicKey,
                    params = createParams()
                )
            )
        }
    }

    // One-shot path now handled by AccumulatingVerifyFunction in createVerifyFunction
}
