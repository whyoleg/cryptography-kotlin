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

// works only over pre-hashed data
internal abstract class Openssl3PhSignatureVerifier(
    private val publicKey: CPointer<EVP_PKEY>,
) : SignatureVerifier {
    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = publicKey.upRef().cleaner()

    protected abstract fun MemScope.createParams(): CValuesRef<OSSL_PARAM>?

    override fun createVerifyFunction(): VerifyFunction = AccumulatingVerifyFunction(::verify)

    @OptIn(UnsafeNumber::class)
    private fun verify(data: ByteArray, signature: ByteArray): String? = with_PKEY_CTX(publicKey) { context ->
        checkError(EVP_PKEY_verify_init_ex(context, createParams()))

        data.usePinned { dataPin ->
            signature.usePinned { sigPin ->
                val result = EVP_PKEY_verify(
                    ctx = context,
                    sig = sigPin.safeAddressOfU(0),
                    siglen = signature.size.convert(),
                    tbs = dataPin.safeAddressOfU(0),
                    tbslen = data.size.convert()
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
    }
}
