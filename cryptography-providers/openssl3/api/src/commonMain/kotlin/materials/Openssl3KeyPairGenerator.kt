/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.openssl3.materials

import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.openssl3.internal.*
import dev.whyoleg.cryptography.openssl3.internal.cinterop.*
import kotlinx.cinterop.*

internal abstract class Openssl3KeyPairGenerator<K : Key>(
    private val algorithm: String,
) : KeyGenerator<K> {
    protected abstract fun MemScope.createParams(): CValuesRef<OSSL_PARAM>?
    protected abstract fun wrapKeyPair(keyPair: CPointer<EVP_PKEY>): K

    final override fun generateKeyBlocking(): K = memScoped {
        val context = checkError(EVP_PKEY_CTX_new_from_name(null, algorithm, null))
        try {
            checkError(EVP_PKEY_keygen_init(context))
            checkError(EVP_PKEY_CTX_set_params(context, createParams()))
            val pkeyVar = alloc<CPointerVar<EVP_PKEY>>()
            checkError(EVP_PKEY_generate(context, pkeyVar.ptr))
            val pkey = checkError(pkeyVar.value)
            //we do upRef here, because key pair contains 2 separate instances: public and private key
            wrapKeyPair(pkey.upRef())
        } finally {
            EVP_PKEY_CTX_free(context)
        }
    }
}
