/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
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

internal class JdkX25519(
    private val state: JdkCryptographyState,
) : X25519 {
    override fun publicKeyDecoder(): KeyDecoder<X25519.PublicKey.Format, X25519.PublicKey> = X25519PublicKeyDecoder()

    override fun privateKeyDecoder(): KeyDecoder<X25519.PrivateKey.Format, X25519.PrivateKey> = X25519PrivateKeyDecoder()

    override fun keyPairGenerator(): KeyGenerator<X25519.KeyPair> = X25519KeyPairGenerator()

    private inner class X25519KeyPairGenerator : JdkKeyPairGenerator<X25519.KeyPair>(state, "X25519") {
        override fun JKeyPairGenerator.init() {
            // X25519 doesn't require parameters
        }

        override fun JKeyPair.convert(): X25519.KeyPair {
            val publicKey = X25519PublicKey(public)
            val privateKey = X25519PrivateKey(private, publicKey)
            return X25519KeyPair(publicKey, privateKey)
        }
    }

    private inner class X25519PublicKeyDecoder : JdkPublicKeyDecoder<X25519.PublicKey.Format, X25519.PublicKey>(state, "X25519") {
        override fun JPublicKey.convert(): X25519.PublicKey = X25519PublicKey(this)

        override fun decodeFromByteArrayBlocking(format: X25519.PublicKey.Format, bytes: ByteArray): X25519.PublicKey = when (format) {
            X25519.PublicKey.Format.RAW -> decodeFromDer(wrapSubjectPublicKeyInfo(X25519AlgorithmIdentifier, bytes))
            X25519.PublicKey.Format.DER -> decodeFromDer(bytes)
            X25519.PublicKey.Format.PEM -> decodeFromDer(unwrapPem(PemLabel.PublicKey, bytes))
        }
    }

    private inner class X25519PrivateKeyDecoder : JdkPrivateKeyDecoder<X25519.PrivateKey.Format, X25519.PrivateKey>(state, "X25519") {
        private val publicKeyDecoder = X25519PublicKeyDecoder()

        override fun JPrivateKey.convert(): X25519.PrivateKey = X25519PrivateKey(this, null)

        override fun decodeFromByteArrayBlocking(format: X25519.PrivateKey.Format, bytes: ByteArray): X25519.PrivateKey = when (format) {
            X25519.PrivateKey.Format.RAW -> {
                // X25519 private key is a 32-byte key, wrapped as OCTET STRING inside PKCS#8
                val wrappedKey = Der.encodeToByteArray(ByteArraySerializer(), bytes)
                decodeFromDer(wrapPrivateKeyInfo(0, X25519AlgorithmIdentifier, wrappedKey))
            }
            X25519.PrivateKey.Format.DER -> decodeFromDer(bytes)
            X25519.PrivateKey.Format.PEM -> decodeFromDer(unwrapPem(PemLabel.PrivateKey, bytes))
        }

        override fun decodeFromDer(input: ByteArray): X25519.PrivateKey {
            val privateKey = decodeFromDerRaw(input)
            // Try to extract public key from PrivateKeyInfo if present
            val publicKey = try {
                val pki = Der.decodeFromByteArray(PrivateKeyInfo.serializer(), input)
                pki.publicKey?.let { bitArray ->
                    publicKeyDecoder.decodeFromByteArrayBlocking(X25519.PublicKey.Format.RAW, bitArray.byteArray)
                }
            } catch (_: Exception) {
                null
            }
            return X25519PrivateKey(privateKey, publicKey)
        }
    }

    private class X25519KeyPair(
        override val publicKey: X25519.PublicKey,
        override val privateKey: X25519.PrivateKey,
    ) : X25519.KeyPair

    private inner class X25519PublicKey(
        val key: JPublicKey,
    ) : X25519.PublicKey, JdkEncodableKey<X25519.PublicKey.Format>(key), SharedSecretGenerator<X25519.PrivateKey> {
        private val keyAgreement = state.keyAgreement("X25519")

        override fun encodeToByteArrayBlocking(format: X25519.PublicKey.Format): ByteArray = when (format) {
            X25519.PublicKey.Format.RAW -> unwrapSubjectPublicKeyInfo(ObjectIdentifier.X25519, encodeToDer())
            X25519.PublicKey.Format.DER -> encodeToDer()
            X25519.PublicKey.Format.PEM -> wrapPem(PemLabel.PublicKey, encodeToDer())
        }

        override fun sharedSecretGenerator(): SharedSecretGenerator<X25519.PrivateKey> = this

        override fun generateSharedSecretToByteArrayBlocking(other: X25519.PrivateKey): ByteArray {
            check(other is X25519PrivateKey) { "Only key produced by JDK provider is supported" }
            return keyAgreement.doAgreement(state, other.key, key)
        }
    }

    private inner class X25519PrivateKey(
        val key: JPrivateKey,
        private var publicKey: X25519.PublicKey?,
    ) : X25519.PrivateKey, JdkEncodableKey<X25519.PrivateKey.Format>(key), SharedSecretGenerator<X25519.PublicKey> {
        private val keyAgreement = state.keyAgreement("X25519")

        override fun getPublicKeyBlocking(): X25519.PublicKey {
            if (publicKey == null) {
                // Derive public key by re-encoding and re-decoding through PKCS#8
                // JDK's X25519 implementation includes public key in the encoded form
                val derBytes = encodeToDer()
                val pki = Der.decodeFromByteArray(PrivateKeyInfo.serializer(), derBytes)
                val pubKeyBytes = pki.publicKey?.byteArray
                    ?: error("Cannot derive public key from X25519 private key: public key not present in encoding")
                publicKey = X25519PublicKeyDecoder().decodeFromByteArrayBlocking(X25519.PublicKey.Format.RAW, pubKeyBytes)
            }
            return publicKey!!
        }

        override fun encodeToByteArrayBlocking(format: X25519.PrivateKey.Format): ByteArray = when (format) {
            X25519.PrivateKey.Format.RAW -> {
                // Extract the 32-byte key from PKCS#8 encoding
                val pki = Der.decodeFromByteArray(PrivateKeyInfo.serializer(), encodeToDer())
                // The private key is wrapped as an OCTET STRING containing the 32-byte key
                Der.decodeFromByteArray(ByteArraySerializer(), pki.privateKey)
            }
            X25519.PrivateKey.Format.DER -> encodeToDer()
            X25519.PrivateKey.Format.PEM -> wrapPem(PemLabel.PrivateKey, encodeToDer())
        }

        override fun sharedSecretGenerator(): SharedSecretGenerator<X25519.PublicKey> = this

        override fun generateSharedSecretToByteArrayBlocking(other: X25519.PublicKey): ByteArray {
            check(other is X25519PublicKey) { "Only key produced by JDK provider is supported" }
            return keyAgreement.doAgreement(state, key, other.key)
        }
    }
}