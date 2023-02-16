package dev.whyoleg.cryptography.openssl3.materials

import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.openssl3.internal.*
import dev.whyoleg.kcwrapper.libcrypto3.cinterop.*
import kotlinx.cinterop.*

internal abstract class Openssl3KeyPairGenerator<K : Key>(
    private val algorithm: String,
) : KeyGenerator<K> {
    protected abstract fun MemScope.createParams(): CValuesRef<OSSL_PARAM>?
    protected abstract fun wrapKeyPair(keyPair: CPointer<EVP_PKEY>): K

    final override fun generateKeyBlocking(): K = memScoped {
        val context = checkNotNull(EVP_PKEY_CTX_new_from_name(null, algorithm, null)) { "Failed to create PKEY_CTX context" }
        try {
            checkError(EVP_PKEY_keygen_init(context))
            checkError(EVP_PKEY_CTX_set_params(context, createParams()))
            val pkeyVar = alloc<CPointerVar<EVP_PKEY>>()
            checkError(EVP_PKEY_generate(context, pkeyVar.ptr))
            val pkey = checkNotNull(pkeyVar.value) { "Failed to generate key pair" }
            //we do upRef here, because key pair contains 2 separate instances: public and private key
            wrapKeyPair(pkey.upRef())
        } finally {
            EVP_PKEY_CTX_free(context)
        }
    }
}
