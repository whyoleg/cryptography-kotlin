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
import kotlin.experimental.*

internal abstract class Openssl3DigestSignatureVerifier(
    private val publicKey: CPointer<EVP_PKEY>,
    private val hashAlgorithm: String?,
) : SignatureVerifier {
    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = publicKey.upRef().cleaner()

    protected abstract fun MemScope.createParams(): CValuesRef<OSSL_PARAM>?

    // in case of no digest, streaming is not supported
    override fun createVerifyFunction(): VerifyFunction = if (hashAlgorithm == null) {
        AccumulatingVerifyFunction(::verify)
    } else {
        Openssl3DigestVerifyFunction(Resource(checkError(EVP_MD_CTX_new()), ::EVP_MD_CTX_free))
    }

    // one shot
    @OptIn(UnsafeNumber::class)
    private fun verify(data: ByteArray, signature: ByteArray): String? = memScoped {
        val context = checkError(EVP_MD_CTX_new())
        try {
            init(context)

            data.usePinned { dataPin ->
                signature.usePinned { sigPin ->
                    val result = EVP_DigestVerify(
                        context,
                        sigPin.safeAddressOfU(0),
                        signature.size.convert(),
                        dataPin.safeAddressOfU(0),
                        data.size.convert()
                    )
                    // 0     - means verification failed
                    // 1     - means verification succeeded
                    // other - means error
                    when {
                        result == 1 -> null // success
                        result == 0 -> "Signature verification failed" // verification failed
                        else        -> {
                            checkError(result) // will throw
                            null // unreachable
                        }
                    }
                }
            }
        } finally {
            EVP_MD_CTX_free(context)
        }
    }

    private fun MemScope.init(context: CPointer<EVP_MD_CTX>) {
        checkError(
            EVP_DigestVerifyInit_ex(
                ctx = context,
                pctx = null,
                mdname = hashAlgorithm,
                libctx = null,
                props = null,
                pkey = publicKey,
                params = createParams()
            )
        )
    }

    // inner class to have a reference to class with cleaner
    private inner class Openssl3DigestVerifyFunction(
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
            init(context.access())
        }
    }
}
