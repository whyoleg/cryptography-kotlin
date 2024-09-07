/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.operations

import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*
import kotlin.experimental.*

internal abstract class Openssl3DigestSignatureVerifier(
    private val publicKey: CPointer<EVP_PKEY>,
    private val hashAlgorithm: String,
) : SignatureVerifier {
    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = publicKey.upRef().cleaner()

    protected abstract fun MemScope.createParams(): CValuesRef<OSSL_PARAM>?

    @OptIn(UnsafeNumber::class)
    override fun verifySignatureBlocking(data: ByteArray, signature: ByteArray): Boolean = memScoped {
        val context = checkError(EVP_MD_CTX_new())
        try {
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

            checkError(EVP_DigestVerifyUpdate(context, data.safeRefTo(0), data.size.convert()))

            val result = EVP_DigestVerifyFinal(context, signature.safeRefToU(0), signature.size.convert())
            // 0     - means verification failed
            // 1     - means verification succeeded
            // other - means error
            if (result != 0) checkError(result)
            result == 1
        } finally {
            EVP_MD_CTX_free(context)
        }
    }
}
