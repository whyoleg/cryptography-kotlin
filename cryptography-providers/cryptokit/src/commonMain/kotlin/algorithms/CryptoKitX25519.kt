/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.cryptokit.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.base.materials.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.swift.DwcCryptoKitInterop.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.pem.*
import kotlinx.cinterop.*
import platform.Foundation.*

@OptIn(UnsafeNumber::class)
internal object CryptoKitX25519 : X25519 {
    override fun publicKeyDecoder(): KeyDecoder<X25519.PublicKey.Format, X25519.PublicKey> = X25519PublicKeyDecoder

    override fun privateKeyDecoder(): KeyDecoder<X25519.PrivateKey.Format, X25519.PrivateKey> = X25519PrivateKeyDecoder

    override fun keyPairGenerator(): KeyGenerator<X25519.KeyPair> = X25519KeyPairGenerator

    private object X25519KeyPairGenerator : KeyGenerator<X25519.KeyPair> {
        override fun generateKeyBlocking(): X25519.KeyPair {
            val privateKey = DwcX25519PrivateKey.generate()
            return X25519KeyPair(
                privateKey = X25519PrivateKey(privateKey),
                publicKey = X25519PublicKey(privateKey.publicKey())
            )
        }
    }

    private object X25519PublicKeyDecoder : KeyDecoder<X25519.PublicKey.Format, X25519.PublicKey> {
        override fun decodeFromByteArrayBlocking(format: X25519.PublicKey.Format, bytes: ByteArray): X25519.PublicKey {
            return X25519PublicKey(swiftTry { error ->
                when (format) {
                    X25519.PublicKey.Format.RAW -> bytes.useNSData { DwcX25519PublicKey.decodeRawWithRawRepresentation(it, error) }
                    X25519.PublicKey.Format.DER -> {
                        val rawBytes = unwrapSubjectPublicKeyInfo(ObjectIdentifier.X25519, bytes)
                        rawBytes.useNSData { DwcX25519PublicKey.decodeRawWithRawRepresentation(it, error) }
                    }
                    X25519.PublicKey.Format.PEM -> {
                        val derBytes = unwrapPem(PemLabel.PublicKey, bytes)
                        val rawBytes = unwrapSubjectPublicKeyInfo(ObjectIdentifier.X25519, derBytes)
                        rawBytes.useNSData { DwcX25519PublicKey.decodeRawWithRawRepresentation(it, error) }
                    }
                }
            })
        }
    }

    private object X25519PrivateKeyDecoder : KeyDecoder<X25519.PrivateKey.Format, X25519.PrivateKey> {
        override fun decodeFromByteArrayBlocking(format: X25519.PrivateKey.Format, bytes: ByteArray): X25519.PrivateKey {
            return X25519PrivateKey(swiftTry { error ->
                when (format) {
                    X25519.PrivateKey.Format.RAW -> bytes.useNSData { DwcX25519PrivateKey.decodeRawWithRawRepresentation(it, error) }
                    X25519.PrivateKey.Format.DER -> {
                        val pki = Der.decodeFromByteArray(PrivateKeyInfo.serializer(), bytes)
                        val rawBytes = Der.decodeFromByteArray(kotlinx.serialization.builtins.ByteArraySerializer(), pki.privateKey)
                        rawBytes.useNSData { DwcX25519PrivateKey.decodeRawWithRawRepresentation(it, error) }
                    }
                    X25519.PrivateKey.Format.PEM -> {
                        val derBytes = unwrapPem(PemLabel.PrivateKey, bytes)
                        val pki = Der.decodeFromByteArray(PrivateKeyInfo.serializer(), derBytes)
                        val rawBytes = Der.decodeFromByteArray(kotlinx.serialization.builtins.ByteArraySerializer(), pki.privateKey)
                        rawBytes.useNSData { DwcX25519PrivateKey.decodeRawWithRawRepresentation(it, error) }
                    }
                }
            })
        }
    }
}

private class X25519KeyPair(
    override val privateKey: X25519.PrivateKey,
    override val publicKey: X25519.PublicKey,
) : X25519.KeyPair

@OptIn(UnsafeNumber::class)
private class X25519PublicKey(
    internal val publicKey: DwcX25519PublicKey,
) : X25519.PublicKey, SharedSecretGenerator<X25519.PrivateKey> {
    override fun encodeToByteArrayBlocking(format: X25519.PublicKey.Format): ByteArray {
        val rawBytes = publicKey.rawRepresentation().toByteArray()
        return when (format) {
            X25519.PublicKey.Format.RAW -> rawBytes
            X25519.PublicKey.Format.DER -> wrapSubjectPublicKeyInfo(X25519AlgorithmIdentifier, rawBytes)
            X25519.PublicKey.Format.PEM -> wrapPem(PemLabel.PublicKey, wrapSubjectPublicKeyInfo(X25519AlgorithmIdentifier, rawBytes))
        }
    }

    override fun sharedSecretGenerator(): SharedSecretGenerator<X25519.PrivateKey> = this

    override fun generateSharedSecretToByteArrayBlocking(other: X25519.PrivateKey): ByteArray {
        check(other is X25519PrivateKey)
        return other.deriveSecret(publicKey)
    }
}

@OptIn(UnsafeNumber::class)
private class X25519PrivateKey(
    private val privateKey: DwcX25519PrivateKey,
) : X25519.PrivateKey, SharedSecretGenerator<X25519.PublicKey> {
    override fun getPublicKeyBlocking(): X25519.PublicKey = X25519PublicKey(privateKey.publicKey())

    override fun encodeToByteArrayBlocking(format: X25519.PrivateKey.Format): ByteArray {
        val rawBytes = privateKey.rawRepresentation().toByteArray()
        return when (format) {
            X25519.PrivateKey.Format.RAW -> rawBytes
            X25519.PrivateKey.Format.DER -> {
                val wrappedSeed = Der.encodeToByteArray(kotlinx.serialization.builtins.ByteArraySerializer(), rawBytes)
                wrapPrivateKeyInfo(0, X25519AlgorithmIdentifier, wrappedSeed)
            }
            X25519.PrivateKey.Format.PEM -> {
                val wrappedSeed = Der.encodeToByteArray(kotlinx.serialization.builtins.ByteArraySerializer(), rawBytes)
                val derBytes = wrapPrivateKeyInfo(0, X25519AlgorithmIdentifier, wrappedSeed)
                wrapPem(PemLabel.PrivateKey, derBytes)
            }
        }
    }

    override fun sharedSecretGenerator(): SharedSecretGenerator<X25519.PublicKey> = this

    override fun generateSharedSecretToByteArrayBlocking(other: X25519.PublicKey): ByteArray {
        check(other is X25519PublicKey)
        return deriveSecret(other.publicKey)
    }

    fun deriveSecret(publicKey: DwcX25519PublicKey): ByteArray {
        return swiftTry { error ->
            privateKey.deriveSecretWithPublicKey(publicKey, error)
        }.toByteArray()
    }
}
