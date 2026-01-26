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

// works only over pre-hashed data
internal abstract class Openssl3PhSignatureGenerator(
    private val privateKey: CPointer<EVP_PKEY>,
) : SignatureGenerator {
    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = privateKey.upRef().cleaner()

    protected abstract fun MemScope.createParams(): CValuesRef<OSSL_PARAM>?

    override fun createSignFunction(): SignFunction = AccumulatingSignFunction(::sign)

    @OptIn(UnsafeNumber::class)
    private fun sign(data: ByteArray): ByteArray = memScoped {
        val context = checkError(EVP_PKEY_CTX_new_from_pkey(null, privateKey, null))
        try {
            checkError(EVP_PKEY_sign_init_ex(context, createParams()))

            data.usePinned { dataPin ->
                val siglen = alloc<size_tVar>()
                checkError(
                    EVP_PKEY_sign(
                        ctx = context,
                        sig = null,
                        siglen = siglen.ptr,
                        tbs = dataPin.safeAddressOfU(0),
                        tbslen = data.size.convert()
                    )
                )
                val signature = ByteArray(siglen.value.convert())
                checkError(
                    EVP_PKEY_sign(
                        ctx = context,
                        sig = signature.safeRefToU(0),
                        siglen = siglen.ptr,
                        tbs = dataPin.safeAddressOfU(0),
                        tbslen = data.size.convert()
                    )
                )
                signature.ensureSizeExactly(siglen.value.convert())
            }
        } finally {
            EVP_PKEY_CTX_free(context)
        }
    }
}
