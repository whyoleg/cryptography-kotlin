/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.operations.*
import kotlinx.cinterop.*

internal object Openssl3Ecdsa : Openssl3Ec<ECDSA.PublicKey, ECDSA.PrivateKey, ECDSA.KeyPair>(
    wrapPublicKey = ::EcdsaPublicKey,
    wrapPrivateKey = ::EcdsaPrivateKey,
    wrapKeyPair = ::EcdsaKeyPair,
), ECDSA {
    private class EcdsaKeyPair(
        override val publicKey: ECDSA.PublicKey,
        override val privateKey: ECDSA.PrivateKey,
    ) : ECDSA.KeyPair

    private class EcdsaPrivateKey(
        curve: EC.Curve,
        key: CPointer<EVP_PKEY>,
        publicKey: ECDSA.PublicKey?,
    ) : Openssl3EcPrivateKey(curve, key, publicKey), ECDSA.PrivateKey {
        override fun signatureGenerator(digest: CryptographyAlgorithmId<Digest>?, format: ECDSA.SignatureFormat): SignatureGenerator {
            val derSignatureGenerator = when (digest) {
                null -> EcdsaPhSignatureGenerator(key)
                else -> EcdsaDigestSignatureGenerator(key, hashAlgorithmName(digest))
            }
            return when (format) {
                ECDSA.SignatureFormat.DER -> derSignatureGenerator
                ECDSA.SignatureFormat.RAW -> EcdsaRawSignatureGenerator(derSignatureGenerator, EC_order_size(key))
            }
        }
    }

    private class EcdsaPublicKey(
        curve: EC.Curve,
        key: CPointer<EVP_PKEY>,
    ) : Openssl3EcPublicKey(curve, key), ECDSA.PublicKey {
        override fun signatureVerifier(digest: CryptographyAlgorithmId<Digest>?, format: ECDSA.SignatureFormat): SignatureVerifier {
            val derSignatureVerifier = when (digest) {
                null -> EcdsaPhSignatureVerifier(key)
                else -> EcdsaDigestSignatureVerifier(key, hashAlgorithmName(digest))
            }
            return when (format) {
                ECDSA.SignatureFormat.DER -> derSignatureVerifier
                ECDSA.SignatureFormat.RAW -> EcdsaRawSignatureVerifier(derSignatureVerifier, EC_order_size(key))
            }
        }
    }
}

private class EcdsaPhSignatureGenerator(
    privateKey: CPointer<EVP_PKEY>,
) : Openssl3PhSignatureGenerator(privateKey) {
    override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = null
}

private class EcdsaDigestSignatureGenerator(
    privateKey: CPointer<EVP_PKEY>,
    hashAlgorithm: String,
) : Openssl3DigestSignatureGenerator(privateKey, hashAlgorithm) {
    override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = null
}

private class EcdsaPhSignatureVerifier(
    publicKey: CPointer<EVP_PKEY>,
) : Openssl3PhSignatureVerifier(publicKey) {
    override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = null
}

private class EcdsaDigestSignatureVerifier(
    publicKey: CPointer<EVP_PKEY>,
    hashAlgorithm: String,
) : Openssl3DigestSignatureVerifier(publicKey, hashAlgorithm) {
    override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = null
}
