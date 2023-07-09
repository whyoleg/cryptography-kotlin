/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.algorithms.asymmetric.RSA
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.operations.*
import dev.whyoleg.cryptography.operations.signature.*
import kotlinx.cinterop.*

internal object Openssl3RsaPkcs1 : Openssl3Rsa<RSA.PKCS1.PublicKey, RSA.PKCS1.PrivateKey, RSA.PKCS1.KeyPair>(), RSA.PKCS1 {
    override fun wrapKeyPair(hashAlgorithm: String, keyPair: CPointer<EVP_PKEY>): RSA.PKCS1.KeyPair = RsaPkcs1KeyPair(
        publicKey = RsaPkcs1PublicKey(keyPair, hashAlgorithm),
        privateKey = RsaPkcs1PrivateKey(keyPair, hashAlgorithm),
    )

    override fun wrapPublicKey(hashAlgorithm: String, publicKey: CPointer<EVP_PKEY>): RSA.PKCS1.PublicKey =
        RsaPkcs1PublicKey(publicKey, hashAlgorithm)

    override fun wrapPrivateKey(hashAlgorithm: String, privateKey: CPointer<EVP_PKEY>): RSA.PKCS1.PrivateKey =
        RsaPkcs1PrivateKey(privateKey, hashAlgorithm)

    private class RsaPkcs1KeyPair(
        override val publicKey: RSA.PKCS1.PublicKey,
        override val privateKey: RSA.PKCS1.PrivateKey,
    ) : RSA.PKCS1.KeyPair

    private class RsaPkcs1PublicKey(
        key: CPointer<EVP_PKEY>,
        private val hashAlgorithm: String,
    ) : RsaPublicKey(key), RSA.PKCS1.PublicKey {
        override fun signatureVerifier(): SignatureVerifier = RsaPkcs1SignatureVerifier(key, hashAlgorithm)
    }

    private class RsaPkcs1PrivateKey(
        key: CPointer<EVP_PKEY>,
        private val hashAlgorithm: String,
    ) : RsaPrivateKey(key), RSA.PKCS1.PrivateKey {
        override fun signatureGenerator(): SignatureGenerator = RsaPkcs1SignatureGenerator(key, hashAlgorithm)
    }
}

private class RsaPkcs1SignatureGenerator(
    privateKey: CPointer<EVP_PKEY>,
    hashAlgorithm: String,
) : Openssl3DigestSignatureGenerator(privateKey, hashAlgorithm) {
    override fun MemScope.createParams(): CValuesRef<OSSL_PARAM> = OSSL_PARAM_array(
        OSSL_PARAM_construct_utf8_string("pad-mode".cstr.ptr, "pkcs1".cstr.ptr, 0U),
    )
}

private class RsaPkcs1SignatureVerifier(
    publicKey: CPointer<EVP_PKEY>,
    hashAlgorithm: String,
) : Openssl3DigestSignatureVerifier(publicKey, hashAlgorithm) {
    override fun MemScope.createParams(): CValuesRef<OSSL_PARAM> = OSSL_PARAM_array(
        OSSL_PARAM_construct_utf8_string("pad-mode".cstr.ptr, "pkcs1".cstr.ptr, 0U),
    )
}
