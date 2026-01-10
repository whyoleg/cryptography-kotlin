/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.materials.*
import kotlinx.cinterop.*
import platform.posix.*
import kotlin.experimental.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.asn1.ObjectIdentifier
import dev.whyoleg.cryptography.providers.base.materials.*
import dev.whyoleg.cryptography.providers.openssl3.operations.Openssl3DigestSignatureGenerator
import dev.whyoleg.cryptography.providers.openssl3.operations.Openssl3DigestSignatureVerifier

internal object Openssl3EdDSA : EdDSA {
    private fun algorithmName(curve: EdDSA.Curve): String = when (curve) {
        EdDSA.Curve.Ed25519 -> "ED25519"
        EdDSA.Curve.Ed448   -> "ED448"
    }
    private fun oid(curve: EdDSA.Curve): ObjectIdentifier = when (curve) {
        EdDSA.Curve.Ed25519 -> ObjectIdentifier.Ed25519
        EdDSA.Curve.Ed448   -> ObjectIdentifier.Ed448
    }

    override fun publicKeyDecoder(curve: EdDSA.Curve): KeyDecoder<EdDSA.PublicKey.Format, EdDSA.PublicKey> =
        object : Openssl3PublicKeyDecoder<EdDSA.PublicKey.Format, EdDSA.PublicKey>(algorithmName(curve)) {
            override fun inputType(format: EdDSA.PublicKey.Format): String = when (format) {
                EdDSA.PublicKey.Format.DER -> "DER"
                EdDSA.PublicKey.Format.PEM -> "PEM"
                EdDSA.PublicKey.Format.JWK,
                EdDSA.PublicKey.Format.RAW -> error("should not be called: handled explicitly in decodeFromBlocking")
            }

            override fun decodeFromByteArrayBlocking(format: EdDSA.PublicKey.Format, bytes: ByteArray): EdDSA.PublicKey = when (format) {
                EdDSA.PublicKey.Format.RAW -> super.decodeFromByteArrayBlocking(
                    EdDSA.PublicKey.Format.DER,
                    wrapSubjectPublicKeyInfo(UnknownKeyAlgorithmIdentifier(oid(curve)), bytes)
                )
                else -> super.decodeFromByteArrayBlocking(format, bytes)
            }

            override fun wrapKey(key: CPointer<EVP_PKEY>): EdDSA.PublicKey = EdDsaPublicKey(key, curve)
        }

    override fun privateKeyDecoder(curve: EdDSA.Curve): KeyDecoder<EdDSA.PrivateKey.Format, EdDSA.PrivateKey> =
        object : Openssl3PrivateKeyDecoder<EdDSA.PrivateKey.Format, EdDSA.PrivateKey>(algorithmName(curve)) {
            override fun inputType(format: EdDSA.PrivateKey.Format): String = when (format) {
                EdDSA.PrivateKey.Format.DER -> "DER"
                EdDSA.PrivateKey.Format.PEM -> "PEM"
                EdDSA.PrivateKey.Format.JWK,
                EdDSA.PrivateKey.Format.RAW -> error("should not be called: handled explicitly in decodeFromBlocking")
            }

            override fun decodeFromByteArrayBlocking(format: EdDSA.PrivateKey.Format, bytes: ByteArray): EdDSA.PrivateKey = when (format) {
                EdDSA.PrivateKey.Format.RAW -> super.decodeFromByteArrayBlocking(
                    EdDSA.PrivateKey.Format.DER,
                    wrapPrivateKeyInfo(0, UnknownKeyAlgorithmIdentifier(oid(curve)), bytes)
                )
                else -> super.decodeFromByteArrayBlocking(format, bytes)
            }

            override fun wrapKey(key: CPointer<EVP_PKEY>): EdDSA.PrivateKey = EdDsaPrivateKey(key, curve)
        }

    override fun keyPairGenerator(curve: EdDSA.Curve): KeyGenerator<EdDSA.KeyPair> =
        object : Openssl3KeyPairGenerator<EdDSA.KeyPair>(algorithmName(curve)) {
            override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = null
            override fun wrapKeyPair(keyPair: CPointer<EVP_PKEY>): EdDSA.KeyPair = EdDsaKeyPair(
                publicKey = EdDsaPublicKey(keyPair, curve),
                privateKey = EdDsaPrivateKey(keyPair, curve)
            )
        }

    private class EdDsaKeyPair(
        override val publicKey: EdDSA.PublicKey,
        override val privateKey: EdDSA.PrivateKey,
    ) : EdDSA.KeyPair

    private class EdDsaPublicKey(
        key: CPointer<EVP_PKEY>,
        private val curve: EdDSA.Curve,
    ) : EdDSA.PublicKey, Openssl3PublicKeyEncodable<EdDSA.PublicKey.Format>(key) {
        override fun outputType(format: EdDSA.PublicKey.Format): String = when (format) {
            EdDSA.PublicKey.Format.DER -> "DER"
            EdDSA.PublicKey.Format.PEM -> "PEM"
            EdDSA.PublicKey.Format.JWK,
            EdDSA.PublicKey.Format.RAW -> error("should not be called: handled explicitly in encodeToBlocking")
        }

        override fun encodeToByteArrayBlocking(format: EdDSA.PublicKey.Format): ByteArray = when (format) {
            EdDSA.PublicKey.Format.RAW -> unwrapSubjectPublicKeyInfo(
                oid(curve),
                super.encodeToByteArrayBlocking(EdDSA.PublicKey.Format.DER)
            )
            else -> super.encodeToByteArrayBlocking(format)
        }

        override fun signatureVerifier(): SignatureVerifier = EdDsaSignatureVerifier(key)
    }

    private class EdDsaPrivateKey(
        key: CPointer<EVP_PKEY>,
        private val curve: EdDSA.Curve,
    ) : EdDSA.PrivateKey, Openssl3PrivateKeyEncodable<EdDSA.PrivateKey.Format>(key) {
        override fun outputType(format: EdDSA.PrivateKey.Format): String = when (format) {
            EdDSA.PrivateKey.Format.DER -> "DER"
            EdDSA.PrivateKey.Format.PEM -> "PEM"
            EdDSA.PrivateKey.Format.JWK,
            EdDSA.PrivateKey.Format.RAW -> error("should not be called: handled explicitly in encodeToBlocking")
        }

        override fun encodeToByteArrayBlocking(format: EdDSA.PrivateKey.Format): ByteArray = when (format) {
            EdDSA.PrivateKey.Format.RAW -> unwrapPrivateKeyInfo(
                oid(curve),
                super.encodeToByteArrayBlocking(EdDSA.PrivateKey.Format.DER)
            )
            else -> super.encodeToByteArrayBlocking(format)
        }

        override fun signatureGenerator(): SignatureGenerator = EdDsaSignatureGenerator(key)
    }
}


private class EdDsaSignatureGenerator(
    private val privateKey: CPointer<EVP_PKEY>,
) : Openssl3DigestSignatureGenerator(privateKey, hashAlgorithm = null) {
    override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = null
}

private class EdDsaSignatureVerifier(
    private val publicKey: CPointer<EVP_PKEY>,
) : Openssl3DigestSignatureVerifier(publicKey, hashAlgorithm = null) {
    override fun MemScope.createParams(): CValuesRef<OSSL_PARAM>? = null
}
