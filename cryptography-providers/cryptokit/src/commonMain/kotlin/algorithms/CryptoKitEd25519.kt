/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.cryptokit.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.base.materials.*
import dev.whyoleg.cryptography.providers.base.operations.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.swift.DwcCryptoKitInterop.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.pem.*
import kotlinx.cinterop.*
import platform.Foundation.*

@OptIn(UnsafeNumber::class)
internal object CryptoKitEd25519 : ED25519 {
    override fun publicKeyDecoder(): KeyDecoder<ED25519.PublicKey.Format, ED25519.PublicKey> = Ed25519PublicKeyDecoder

    override fun privateKeyDecoder(): KeyDecoder<ED25519.PrivateKey.Format, ED25519.PrivateKey> = Ed25519PrivateKeyDecoder

    override fun keyPairGenerator(): KeyGenerator<ED25519.KeyPair> = Ed25519KeyPairGenerator

    private object Ed25519KeyPairGenerator : KeyGenerator<ED25519.KeyPair> {
        override fun generateKeyBlocking(): ED25519.KeyPair {
            val privateKey = DwcEd25519PrivateKey.generate()
            return Ed25519KeyPair(
                privateKey = Ed25519PrivateKey(privateKey),
                publicKey = Ed25519PublicKey(privateKey.publicKey())
            )
        }
    }

    private object Ed25519PublicKeyDecoder : KeyDecoder<ED25519.PublicKey.Format, ED25519.PublicKey> {
        override fun decodeFromByteArrayBlocking(format: ED25519.PublicKey.Format, bytes: ByteArray): ED25519.PublicKey {
            return Ed25519PublicKey(swiftTry { error ->
                when (format) {
                    ED25519.PublicKey.Format.RAW -> bytes.useNSData { DwcEd25519PublicKey.decodeRawWithRawRepresentation(it, error) }
                    ED25519.PublicKey.Format.DER -> {
                        val rawBytes = unwrapSubjectPublicKeyInfo(ObjectIdentifier.Ed25519, bytes)
                        rawBytes.useNSData { DwcEd25519PublicKey.decodeRawWithRawRepresentation(it, error) }
                    }
                    ED25519.PublicKey.Format.PEM -> {
                        val derBytes = unwrapPem(PemLabel.PublicKey, bytes)
                        val rawBytes = unwrapSubjectPublicKeyInfo(ObjectIdentifier.Ed25519, derBytes)
                        rawBytes.useNSData { DwcEd25519PublicKey.decodeRawWithRawRepresentation(it, error) }
                    }
                }
            })
        }
    }

    private object Ed25519PrivateKeyDecoder : KeyDecoder<ED25519.PrivateKey.Format, ED25519.PrivateKey> {
        override fun decodeFromByteArrayBlocking(format: ED25519.PrivateKey.Format, bytes: ByteArray): ED25519.PrivateKey {
            return Ed25519PrivateKey(swiftTry { error ->
                when (format) {
                    ED25519.PrivateKey.Format.RAW -> bytes.useNSData { DwcEd25519PrivateKey.decodeRawWithRawRepresentation(it, error) }
                    ED25519.PrivateKey.Format.DER -> {
                        val pki = Der.decodeFromByteArray(PrivateKeyInfo.serializer(), bytes)
                        val rawBytes = Der.decodeFromByteArray(kotlinx.serialization.builtins.ByteArraySerializer(), pki.privateKey)
                        rawBytes.useNSData { DwcEd25519PrivateKey.decodeRawWithRawRepresentation(it, error) }
                    }
                    ED25519.PrivateKey.Format.PEM -> {
                        val derBytes = unwrapPem(PemLabel.PrivateKey, bytes)
                        val pki = Der.decodeFromByteArray(PrivateKeyInfo.serializer(), derBytes)
                        val rawBytes = Der.decodeFromByteArray(kotlinx.serialization.builtins.ByteArraySerializer(), pki.privateKey)
                        rawBytes.useNSData { DwcEd25519PrivateKey.decodeRawWithRawRepresentation(it, error) }
                    }
                }
            })
        }
    }
}

private class Ed25519KeyPair(
    override val privateKey: ED25519.PrivateKey,
    override val publicKey: ED25519.PublicKey,
) : ED25519.KeyPair

@OptIn(UnsafeNumber::class)
private class Ed25519PublicKey(
    private val publicKey: DwcEd25519PublicKey,
) : ED25519.PublicKey {
    override fun encodeToByteArrayBlocking(format: ED25519.PublicKey.Format): ByteArray {
        val rawBytes = publicKey.rawRepresentation().toByteArray()
        return when (format) {
            ED25519.PublicKey.Format.RAW -> rawBytes
            ED25519.PublicKey.Format.DER -> wrapSubjectPublicKeyInfo(Ed25519AlgorithmIdentifier, rawBytes)
            ED25519.PublicKey.Format.PEM -> wrapPem(PemLabel.PublicKey, wrapSubjectPublicKeyInfo(Ed25519AlgorithmIdentifier, rawBytes))
        }
    }

    override fun signatureVerifier(): SignatureVerifier = Ed25519SignatureVerifier(publicKey)
}

@OptIn(UnsafeNumber::class)
private class Ed25519PrivateKey(
    private val privateKey: DwcEd25519PrivateKey,
) : ED25519.PrivateKey {
    override fun getPublicKeyBlocking(): ED25519.PublicKey = Ed25519PublicKey(privateKey.publicKey())

    override fun encodeToByteArrayBlocking(format: ED25519.PrivateKey.Format): ByteArray {
        val rawBytes = privateKey.rawRepresentation().toByteArray()
        return when (format) {
            ED25519.PrivateKey.Format.RAW -> rawBytes
            ED25519.PrivateKey.Format.DER -> {
                val wrappedSeed = Der.encodeToByteArray(kotlinx.serialization.builtins.ByteArraySerializer(), rawBytes)
                wrapPrivateKeyInfo(0, Ed25519AlgorithmIdentifier, wrappedSeed)
            }
            ED25519.PrivateKey.Format.PEM -> {
                val wrappedSeed = Der.encodeToByteArray(kotlinx.serialization.builtins.ByteArraySerializer(), rawBytes)
                val derBytes = wrapPrivateKeyInfo(0, Ed25519AlgorithmIdentifier, wrappedSeed)
                wrapPem(PemLabel.PrivateKey, derBytes)
            }
        }
    }

    override fun signatureGenerator(): SignatureGenerator = Ed25519SignatureGenerator(privateKey)
}

@OptIn(UnsafeNumber::class)
private class Ed25519SignatureGenerator(
    private val privateKey: DwcEd25519PrivateKey,
) : SignatureGenerator {
    override fun createSignFunction(): SignFunction = AccumulatingSignFunction { data ->
        swiftTry { error ->
            data.useNSData { privateKey.signWithData(it, error) }
        }.toByteArray()
    }
}

@OptIn(UnsafeNumber::class)
private class Ed25519SignatureVerifier(
    private val publicKey: DwcEd25519PublicKey,
) : SignatureVerifier {
    override fun createVerifyFunction(): VerifyFunction = AccumulatingVerifyFunction { data, signature ->
        val isValid = data.useNSData { dataData ->
            signature.useNSData { signatureData ->
                publicKey.verifyWithSignature(signatureData, dataData)
            }
        }
        if (isValid) null else "Signature verification failed"
    }
}
