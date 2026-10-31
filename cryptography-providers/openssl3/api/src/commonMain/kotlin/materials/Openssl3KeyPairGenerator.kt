/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.materials

import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*

internal abstract class Openssl3KeyPairGenerator<K> private constructor(
    private val algorithm: String?,
    private val key: EvpPKey?,
) : KeyGenerator<K> {
    constructor(algorithm: String) : this(algorithm, null)
    constructor(key: EvpPKey) : this(null, key)

    protected abstract fun MemScope.createParams(): CValuesRef<OSSL_PARAM>?
    protected abstract fun wrapKeyPair(keyPair: EvpPKey): K

    final override fun generateKeyBlocking(): K = with_PKEY_CTX(algorithm, key?.access()) { context ->
        checkError(EVP_PKEY_keygen_init(context))
        checkError(EVP_PKEY_CTX_set_params(context, createParams()))
        val pkeyVar = alloc<CPointerVar<EVP_PKEY>>()
        checkError(EVP_PKEY_generate(context, pkeyVar.ptr))
        // public and private keys of the key pair share the same resource
        wrapKeyPair(EvpPKey(checkError(pkeyVar.value)))
    }
}
