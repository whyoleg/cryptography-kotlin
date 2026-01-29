/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.materials.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.materials.*
import dev.whyoleg.cryptography.providers.jdk.operations.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.pem.*
import kotlinx.serialization.builtins.*

internal class JdkEd25519(
    private val state: JdkCryptographyState,
) : ED25519 {
    override fun publicKeyDecoder(): KeyDecoder<ED25519.PublicKey.Format, ED25519.PublicKey> = Ed25519PublicKeyDecoder()

    override fun privateKeyDecoder(): KeyDecoder<ED25519.PrivateKey.Format, ED25519.PrivateKey> = Ed25519PrivateKeyDecoder()

    override fun keyPairGenerator(): KeyGenerator<ED25519.KeyPair> = Ed25519KeyPairGenerator()

    private inner class Ed25519KeyPairGenerator : JdkKeyPairGenerator<ED25519.KeyPair>(state, "Ed25519") {
        override fun JKeyPairGenerator.init() {
            // Ed25519 doesn't require parameters
        }

        override fun JKeyPair.convert(): ED25519.KeyPair {
            val publicKey = Ed25519PublicKey(public)
            val privateKey = Ed25519PrivateKey(private, publicKey)
            return Ed25519KeyPair(publicKey, privateKey)
        }
    }

    private inner class Ed25519PublicKeyDecoder : JdkPublicKeyDecoder<ED25519.PublicKey.Format, ED25519.PublicKey>(state, "Ed25519") {
        override fun JPublicKey.convert(): ED25519.PublicKey = Ed25519PublicKey(this)

        override fun decodeFromByteArrayBlocking(format: ED25519.PublicKey.Format, bytes: ByteArray): ED25519.PublicKey = when (format) {
            ED25519.PublicKey.Format.RAW -> decodeFromDer(wrapSubjectPublicKeyInfo(Ed25519AlgorithmIdentifier, bytes))
            ED25519.PublicKey.Format.DER -> decodeFromDer(bytes)
            ED25519.PublicKey.Format.PEM -> decodeFromDer(unwrapPem(PemLabel.PublicKey, bytes))
        }
    }

    private inner class Ed25519PrivateKeyDecoder : JdkPrivateKeyDecoder<ED25519.PrivateKey.Format, ED25519.PrivateKey>(state, "Ed25519") {
        private val publicKeyDecoder = Ed25519PublicKeyDecoder()

        override fun JPrivateKey.convert(): ED25519.PrivateKey = Ed25519PrivateKey(this, null)

        override fun decodeFromByteArrayBlocking(format: ED25519.PrivateKey.Format, bytes: ByteArray): ED25519.PrivateKey = when (format) {
            ED25519.PrivateKey.Format.RAW -> {
                // ED25519 private key is a 32-byte seed, wrapped as OCTET STRING inside PKCS#8
                val wrappedSeed = Der.encodeToByteArray(ByteArraySerializer(), bytes)
                decodeFromDer(wrapPrivateKeyInfo(0, Ed25519AlgorithmIdentifier, wrappedSeed))
            }
            ED25519.PrivateKey.Format.DER -> decodeFromDer(bytes)
            ED25519.PrivateKey.Format.PEM -> decodeFromDer(unwrapPem(PemLabel.PrivateKey, bytes))
        }

        override fun decodeFromDer(input: ByteArray): ED25519.PrivateKey {
            val privateKey = decodeFromDerRaw(input)
            // Try to extract public key from PrivateKeyInfo if present
            val publicKey = try {
                val pki = Der.decodeFromByteArray(PrivateKeyInfo.serializer(), input)
                pki.publicKey?.let { bitArray ->
                    publicKeyDecoder.decodeFromByteArrayBlocking(ED25519.PublicKey.Format.RAW, bitArray.byteArray)
                }
            } catch (_: Exception) {
                null
            }
            return Ed25519PrivateKey(privateKey, publicKey)
        }
    }

    private class Ed25519KeyPair(
        override val publicKey: ED25519.PublicKey,
        override val privateKey: ED25519.PrivateKey,
    ) : ED25519.KeyPair

    private inner class Ed25519PublicKey(
        val key: JPublicKey,
    ) : ED25519.PublicKey, JdkEncodableKey<ED25519.PublicKey.Format>(key) {
        override fun encodeToByteArrayBlocking(format: ED25519.PublicKey.Format): ByteArray = when (format) {
            ED25519.PublicKey.Format.RAW -> unwrapSubjectPublicKeyInfo(ObjectIdentifier.Ed25519, encodeToDer())
            ED25519.PublicKey.Format.DER -> encodeToDer()
            ED25519.PublicKey.Format.PEM -> wrapPem(PemLabel.PublicKey, encodeToDer())
        }

        override fun signatureVerifier(): SignatureVerifier = JdkSignatureVerifier(state, key, "Ed25519", null)
    }

    private inner class Ed25519PrivateKey(
        val key: JPrivateKey,
        private var publicKey: ED25519.PublicKey?,
    ) : ED25519.PrivateKey, JdkEncodableKey<ED25519.PrivateKey.Format>(key) {
        override fun getPublicKeyBlocking(): ED25519.PublicKey {
            if (publicKey == null) {
                // Derive public key by re-encoding and re-decoding through PKCS#8
                // JDK's Ed25519 implementation includes public key in the encoded form
                val derBytes = encodeToDer()
                val pki = Der.decodeFromByteArray(PrivateKeyInfo.serializer(), derBytes)
                val pubKeyBytes = pki.publicKey?.byteArray
                    ?: error("Cannot derive public key from Ed25519 private key: public key not present in encoding")
                publicKey = Ed25519PublicKeyDecoder().decodeFromByteArrayBlocking(ED25519.PublicKey.Format.RAW, pubKeyBytes)
            }
            return publicKey!!
        }

        override fun encodeToByteArrayBlocking(format: ED25519.PrivateKey.Format): ByteArray = when (format) {
            ED25519.PrivateKey.Format.RAW -> {
                // Extract the 32-byte seed from PKCS#8 encoding
                val pki = Der.decodeFromByteArray(PrivateKeyInfo.serializer(), encodeToDer())
                // The private key is wrapped as an OCTET STRING containing the 32-byte seed
                Der.decodeFromByteArray(ByteArraySerializer(), pki.privateKey)
            }
            ED25519.PrivateKey.Format.DER -> encodeToDer()
            ED25519.PrivateKey.Format.PEM -> wrapPem(PemLabel.PrivateKey, encodeToDer())
        }

        override fun signatureGenerator(): SignatureGenerator = JdkSignatureGenerator(state, key, "Ed25519", null)
    }
}
