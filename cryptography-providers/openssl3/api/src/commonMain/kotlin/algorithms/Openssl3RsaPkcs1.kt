/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.operations.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.operations.*
import kotlinx.cinterop.*
import kotlin.experimental.*

internal object Openssl3RsaPkcs1 : Openssl3Rsa<RSA.PKCS1.PublicKey, RSA.PKCS1.PrivateKey, RSA.PKCS1.KeyPair>(
    wrapPublicKey = ::RsaPkcs1PublicKey,
    wrapPrivateKey = ::RsaPkcs1PrivateKey,
    wrapKeyPair = ::RsaPkcs1KeyPair,
), RSA.PKCS1 {
    private class RsaPkcs1KeyPair(
        override val publicKey: RSA.PKCS1.PublicKey,
        override val privateKey: RSA.PKCS1.PrivateKey,
    ) : RSA.PKCS1.KeyPair

    private class RsaPkcs1PublicKey(
        key: CPointer<EVP_PKEY>,
        private val hashAlgorithm: String,
    ) : RsaPublicKey(key), RSA.PKCS1.PublicKey {
        override fun signatureVerifier(): SignatureVerifier = RsaPkcs1SignatureVerifier(key, hashAlgorithm)
        override fun encryptor(): Encryptor = RsaPkcs1Encryptor(key)
    }

    private class RsaPkcs1PrivateKey(
        key: CPointer<EVP_PKEY>,
        hashAlgorithm: String,
        publicKey: RSA.PKCS1.PublicKey?,
    ) : RsaPrivateKey(key, hashAlgorithm, publicKey), RSA.PKCS1.PrivateKey {
        override fun signatureGenerator(): SignatureGenerator = RsaPkcs1SignatureGenerator(key, hashAlgorithm)
        override fun decryptor(): Decryptor = RsaPkcs1Decryptor(key)
    }
}

private class RsaPkcs1SignatureGenerator(
    privateKey: CPointer<EVP_PKEY>,
    hashAlgorithm: String,
) : Openssl3DigestSignatureGenerator(privateKey, hashAlgorithm) {
    @OptIn(UnsafeNumber::class)
    override fun MemScope.createParams(): CValuesRef<OSSL_PARAM> = OSSL_PARAM_array(
        OSSL_PARAM_construct_utf8_string("pad-mode".cstr.ptr, "pkcs1".cstr.ptr, 0.convert()),
    )
}

private class RsaPkcs1SignatureVerifier(
    publicKey: CPointer<EVP_PKEY>,
    hashAlgorithm: String,
) : Openssl3DigestSignatureVerifier(publicKey, hashAlgorithm) {
    @OptIn(UnsafeNumber::class)
    override fun MemScope.createParams(): CValuesRef<OSSL_PARAM> = OSSL_PARAM_array(
        OSSL_PARAM_construct_utf8_string("pad-mode".cstr.ptr, "pkcs1".cstr.ptr, 0.convert()),
    )
}

private class RsaPkcs1Encryptor(
    private val publicKey: CPointer<EVP_PKEY>,
) : BaseEncryptor {
    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = publicKey.upRef().cleaner()

    @OptIn(UnsafeNumber::class)
    override fun createEncryptFunction(): CipherFunction {
        return EvpPKeyCipherFunction(publicKey, encrypt = true) {
            OSSL_PARAM_array(
                OSSL_PARAM_construct_utf8_string("pad-mode".cstr.ptr, "pkcs1".cstr.ptr, 0.convert()),
            )
        }
    }
}

private class RsaPkcs1Decryptor(
    private val privateKey: CPointer<EVP_PKEY>,
) : BaseDecryptor {
    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = privateKey.upRef().cleaner()

    @OptIn(UnsafeNumber::class)
    override fun createDecryptFunction(): CipherFunction {
        return EvpPKeyCipherFunction(privateKey, encrypt = false) {
            OSSL_PARAM_array(
                OSSL_PARAM_construct_utf8_string("pad-mode".cstr.ptr, "pkcs1".cstr.ptr, 0.convert()),
            )
        }
    }
}
