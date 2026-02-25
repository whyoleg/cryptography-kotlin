/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.materials.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.materials.*
import dev.whyoleg.cryptography.providers.openssl3.operations.*
import kotlinx.cinterop.*

internal object Openssl3EdDsa : EdDSA {
    override fun publicKeyDecoder(curve: EdDSA.Curve): Decoder<EdDSA.PublicKey.Format, EdDSA.PublicKey> = PublicKeyDecoder(curve)
    override fun privateKeyDecoder(curve: EdDSA.Curve): Decoder<EdDSA.PrivateKey.Format, EdDSA.PrivateKey> = PrivateKeyDecoder(curve)
    override fun keyPairGenerator(curve: EdDSA.Curve): KeyGenerator<EdDSA.KeyPair> = KeyPairGenerator(curve)

    private class PublicKeyDecoder(
        private val curve: EdDSA.Curve,
    ) : Openssl3PublicKeyDecoder<EdDSA.PublicKey.Format, EdDSA.PublicKey>(curve.name) {
        override fun inputType(format: EdDSA.PublicKey.Format): String = when (format) {
            EdDSA.PublicKey.Format.DER -> "DER"
            EdDSA.PublicKey.Format.PEM -> "PEM"
            EdDSA.PublicKey.Format.JWK,
            EdDSA.PublicKey.Format.RAW,
                                       -> error("should not be called: handled explicitly in decodeFromBlocking")
        }

        override fun decodeFromByteArrayBlocking(format: EdDSA.PublicKey.Format, bytes: ByteArray): EdDSA.PublicKey = when (format) {
            EdDSA.PublicKey.Format.RAW -> decodeRaw(bytes)
            EdDSA.PublicKey.Format.JWK -> decodeRaw(JsonWebKeys.decodeOkpPublicKey(curve.name, bytes))
            else                       -> super.decodeFromByteArrayBlocking(format, bytes)
        }

        override fun wrapKey(key: CPointer<EVP_PKEY>): EdDSA.PublicKey = EdDsaPublicKey(curve, key)

        private fun decodeRaw(bytes: ByteArray): EdDSA.PublicKey {
            val type = when (curve) {
                EdDSA.Curve.Ed25519 -> EVP_PKEY_ED25519
                EdDSA.Curve.Ed448   -> EVP_PKEY_ED448
            }
            return wrapKey(decodeRawPublicKey(type, bytes))
        }
    }

    private class PrivateKeyDecoder(
        private val curve: EdDSA.Curve,
    ) : Openssl3PrivateKeyDecoder<EdDSA.PrivateKey.Format, EdDSA.PrivateKey>(curve.name) {
        override fun inputType(format: EdDSA.PrivateKey.Format): String = when (format) {
            EdDSA.PrivateKey.Format.DER -> "DER"
            EdDSA.PrivateKey.Format.PEM -> "PEM"
            EdDSA.PrivateKey.Format.JWK,
            EdDSA.PrivateKey.Format.RAW,
                                        -> error("should not be called: handled explicitly in decodeFromBlocking")
        }

        override fun decodeFromByteArrayBlocking(format: EdDSA.PrivateKey.Format, bytes: ByteArray): EdDSA.PrivateKey = when (format) {
            EdDSA.PrivateKey.Format.RAW -> decodeRaw(bytes)
            EdDSA.PrivateKey.Format.JWK -> decodeRaw(JsonWebKeys.decodeOkpPrivateKey(curve.name, bytes).privateKey)
            else                        -> super.decodeFromByteArrayBlocking(format, bytes)
        }

        override fun wrapKey(key: CPointer<EVP_PKEY>): EdDSA.PrivateKey = EdDsaPrivateKey(curve, key)

        private fun decodeRaw(bytes: ByteArray): EdDSA.PrivateKey {
            val type = when (curve) {
                EdDSA.Curve.Ed25519 -> EVP_PKEY_ED25519
                EdDSA.Curve.Ed448   -> EVP_PKEY_ED448
            }
            return wrapKey(decodeRawPrivateKey(type, bytes))
        }
    }


    private class KeyPairGenerator(
        private val curve: EdDSA.Curve,
    ) : Openssl3KeyPairGenerator<EdDSA.KeyPair>(curve.name) {
        override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = null
        override fun wrapKeyPair(keyPair: CPointer<EVP_PKEY>): EdDSA.KeyPair {
            val publicKey = EdDsaPublicKey(curve, keyPair)
            return EdDsaKeyPair(
                publicKey = publicKey,
                privateKey = EdDsaPrivateKey(curve, keyPair, publicKey)
            )
        }
    }

    private class EdDsaKeyPair(
        override val publicKey: EdDSA.PublicKey,
        override val privateKey: EdDSA.PrivateKey,
    ) : EdDSA.KeyPair

    private class EdDsaPublicKey(
        private val curve: EdDSA.Curve,
        key: CPointer<EVP_PKEY>,
    ) : EdDSA.PublicKey, Openssl3PublicKeyEncodable<EdDSA.PublicKey.Format>(key) {
        override fun outputType(format: EdDSA.PublicKey.Format): String = when (format) {
            EdDSA.PublicKey.Format.DER -> "DER"
            EdDSA.PublicKey.Format.PEM -> "PEM"
            EdDSA.PublicKey.Format.JWK,
            EdDSA.PublicKey.Format.RAW,
                                       -> error("should not be called: handled explicitly in encodeToBlocking")
        }

        override fun encodeToByteArrayBlocking(format: EdDSA.PublicKey.Format): ByteArray = when (format) {
            EdDSA.PublicKey.Format.JWK -> JsonWebKeys.encodeOkpPublicKey(
                curve = curve.name,
                publicKey = encodeRawPublicKey(key),
            )
            EdDSA.PublicKey.Format.RAW -> encodeRawPublicKey(key)
            else                       -> super.encodeToByteArrayBlocking(format)
        }

        override fun signatureVerifier(): SignatureVerifier = EdDsaSignatureVerifier(key)
    }

    private class EdDsaPrivateKey(
        private val curve: EdDSA.Curve,
        key: CPointer<EVP_PKEY>,
        publicKey: EdDSA.PublicKey? = null,
    ) : EdDSA.PrivateKey, Openssl3PrivateKeyEncodable<EdDSA.PrivateKey.Format, EdDSA.PublicKey>(key, publicKey) {
        override fun wrapPublicKey(key: CPointer<EVP_PKEY>): EdDSA.PublicKey = EdDsaPublicKey(curve, key)

        override fun outputType(format: EdDSA.PrivateKey.Format): String = when (format) {
            EdDSA.PrivateKey.Format.DER -> "DER"
            EdDSA.PrivateKey.Format.PEM -> "PEM"
            EdDSA.PrivateKey.Format.JWK,
            EdDSA.PrivateKey.Format.RAW,
                                        -> error("should not be called: handled explicitly in encodeToBlocking")
        }

        override fun encodeToByteArrayBlocking(format: EdDSA.PrivateKey.Format): ByteArray = when (format) {
            EdDSA.PrivateKey.Format.JWK -> JsonWebKeys.encodeOkpPrivateKey(
                curve = curve.name,
                publicKey = encodeRawPublicKey(key),
                privateKey = encodeRawPrivateKey(key),
            )
            EdDSA.PrivateKey.Format.RAW -> encodeRawPrivateKey(key)
            else                        -> super.encodeToByteArrayBlocking(format)
        }

        override fun signatureGenerator(): SignatureGenerator = EdDsaSignatureGenerator(key)
    }
}

private class EdDsaSignatureGenerator(
    privateKey: CPointer<EVP_PKEY>,
) : Openssl3DigestSignatureGenerator(privateKey, hashAlgorithm = null) {
    override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = null
}

private class EdDsaSignatureVerifier(
    publicKey: CPointer<EVP_PKEY>,
) : Openssl3DigestSignatureVerifier(publicKey, hashAlgorithm = null) {
    override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = null
}
