/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.base.operations.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.operations.*
import kotlinx.cinterop.*
import kotlin.experimental.*

internal object Openssl3RsaOaep : Openssl3Rsa<RSA.OAEP.PublicKey, RSA.OAEP.PrivateKey, RSA.OAEP.KeyPair>(), RSA.OAEP {
    override fun wrapKeyPair(hashAlgorithm: String, keyPair: CPointer<EVP_PKEY>): RSA.OAEP.KeyPair = RsaOaepKeyPair(
        publicKey = RsaOaepPublicKey(keyPair, hashAlgorithm),
        privateKey = RsaOaepPrivateKey(keyPair, hashAlgorithm),
    )

    override fun wrapPublicKey(hashAlgorithm: String, publicKey: CPointer<EVP_PKEY>): RSA.OAEP.PublicKey =
        RsaOaepPublicKey(publicKey, hashAlgorithm)

    override fun wrapPrivateKey(hashAlgorithm: String, privateKey: CPointer<EVP_PKEY>): RSA.OAEP.PrivateKey =
        RsaOaepPrivateKey(privateKey, hashAlgorithm)

    private class RsaOaepKeyPair(
        override val publicKey: RSA.OAEP.PublicKey,
        override val privateKey: RSA.OAEP.PrivateKey,
    ) : RSA.OAEP.KeyPair

    private class RsaOaepPublicKey(
        key: CPointer<EVP_PKEY>,
        hashAlgorithm: String,
    ) : RsaPublicKey(key), RSA.OAEP.PublicKey {
        private val encryptor = RsaOaepEncryptor(key, hashAlgorithm)
        override fun encryptor(): AuthenticatedEncryptor = encryptor
    }

    private class RsaOaepPrivateKey(
        key: CPointer<EVP_PKEY>,
        hashAlgorithm: String,
    ) : RsaPrivateKey(key), RSA.OAEP.PrivateKey {
        private val decryptor = RsaOaepDecryptor(key, hashAlgorithm)
        override fun decryptor(): AuthenticatedDecryptor = decryptor
    }
}

private class RsaOaepEncryptor(
    private val publicKey: CPointer<EVP_PKEY>,
    private val hashAlgorithm: String,
) : BaseAuthenticatedEncryptor {
    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = publicKey.upRef().cleaner()

    @OptIn(UnsafeNumber::class)
    override fun createEncryptFunction(associatedData: ByteArray?): CipherFunction {
        return EvpPKeyCipherFunction(publicKey, encrypt = true) {
            OSSL_PARAM_arrayNotNull(
                OSSL_PARAM_construct_utf8_string("pad-mode".cstr.ptr, "oaep".cstr.ptr, 0.convert()),
                OSSL_PARAM_construct_utf8_string("digest".cstr.ptr, hashAlgorithm.cstr.ptr, 0.convert()),
                associatedData?.let { OSSL_PARAM_construct_octet_string("oaep-label".cstr.ptr, it.safeRefTo(0), it.size.convert()) }
            )
        }
    }
}

private class RsaOaepDecryptor(
    private val privateKey: CPointer<EVP_PKEY>,
    private val hashAlgorithm: String,
) : BaseAuthenticatedDecryptor {
    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = privateKey.upRef().cleaner()

    @OptIn(UnsafeNumber::class)
    override fun createDecryptFunction(associatedData: ByteArray?): CipherFunction {
        return EvpPKeyCipherFunction(privateKey, encrypt = false) {
            OSSL_PARAM_arrayNotNull(
                OSSL_PARAM_construct_utf8_string("pad-mode".cstr.ptr, "oaep".cstr.ptr, 0.convert()),
                OSSL_PARAM_construct_utf8_string("digest".cstr.ptr, hashAlgorithm.cstr.ptr, 0.convert()),
                associatedData?.let { OSSL_PARAM_construct_octet_string("oaep-label".cstr.ptr, it.safeRefTo(0), it.size.convert()) }
            )
        }
    }
}
