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
import kotlinx.serialization.builtins.*

internal object CryptoKitEdDsa : EdDSA {
    override fun publicKeyDecoder(curve: EdDSA.Curve): KeyDecoder<EdDSA.PublicKey.Format, EdDSA.PublicKey> {
        check(curve == EdDSA.Curve.Ed25519) { "CryptoKit supports Ed25519 only" }
        return PublicKeyDecoder
    }

    override fun privateKeyDecoder(curve: EdDSA.Curve): KeyDecoder<EdDSA.PrivateKey.Format, EdDSA.PrivateKey> {
        check(curve == EdDSA.Curve.Ed25519) { "CryptoKit supports Ed25519 only" }
        return PrivateKeyDecoder
    }

    override fun keyPairGenerator(curve: EdDSA.Curve): KeyGenerator<EdDSA.KeyPair> {
        check(curve == EdDSA.Curve.Ed25519) { "CryptoKit supports Ed25519 only" }
        return KeyPairGenerator
    }

    private object KeyPairGenerator : KeyGenerator<EdDSA.KeyPair> {
        override fun generateKeyBlocking(): EdDSA.KeyPair {
            val privateKey = SwiftEdDsaPrivateKey.generate()
            return EdDsaKeyPair(
                publicKey = EdPublicKey(privateKey.publicKey()),
                privateKey = EdPrivateKey(privateKey)
            )
        }
    }

    private object PublicKeyDecoder : KeyDecoder<EdDSA.PublicKey.Format, EdDSA.PublicKey> {
        override fun decodeFromByteArrayBlocking(format: EdDSA.PublicKey.Format, bytes: ByteArray): EdDSA.PublicKey = when (format) {
            EdDSA.PublicKey.Format.RAW -> EdPublicKey(
                swiftTry { error -> bytes.useNSData { SwiftEdDsaPublicKey.decodeRawWithRawRepresentation(it, error) } }
            )
            EdDSA.PublicKey.Format.DER -> {
                val raw = unwrapSubjectPublicKeyInfo(ObjectIdentifier.Ed25519, bytes)
                EdPublicKey(swiftTry { error -> raw.useNSData { SwiftEdDsaPublicKey.decodeRawWithRawRepresentation(it, error) } })
            }
            EdDSA.PublicKey.Format.PEM -> {
                val der = unwrapPem(PemLabel.PublicKey, bytes)
                val raw = unwrapSubjectPublicKeyInfo(ObjectIdentifier.Ed25519, der)
                EdPublicKey(swiftTry { error -> raw.useNSData { SwiftEdDsaPublicKey.decodeRawWithRawRepresentation(it, error) } })
            }
            else                       -> error("$format is not supported by CryptoKit EdDSA")
        }
    }

    private object PrivateKeyDecoder : KeyDecoder<EdDSA.PrivateKey.Format, EdDSA.PrivateKey> {
        override fun decodeFromByteArrayBlocking(format: EdDSA.PrivateKey.Format, bytes: ByteArray): EdDSA.PrivateKey = when (format) {
            EdDSA.PrivateKey.Format.RAW -> EdPrivateKey(
                swiftTry { error -> bytes.useNSData { SwiftEdDsaPrivateKey.decodeRawWithRawRepresentation(it, error) } }
            )
            EdDSA.PrivateKey.Format.DER -> {
                val raw = unwrapPrivateKeyInfoForEdDsaXdh(ObjectIdentifier.Ed25519, bytes)
                EdPrivateKey(swiftTry { error -> raw.useNSData { SwiftEdDsaPrivateKey.decodeRawWithRawRepresentation(it, error) } })
            }
            EdDSA.PrivateKey.Format.PEM -> {
                val der = unwrapPem(PemLabel.PrivateKey, bytes)
                val raw = unwrapPrivateKeyInfoForEdDsaXdh(ObjectIdentifier.Ed25519, der)
                EdPrivateKey(swiftTry { error -> raw.useNSData { SwiftEdDsaPrivateKey.decodeRawWithRawRepresentation(it, error) } })
            }
            else                        -> error("$format is not supported by CryptoKit EdDSA")
        }
    }

    private class EdDsaKeyPair(
        override val publicKey: EdDSA.PublicKey,
        override val privateKey: EdDSA.PrivateKey,
    ) : EdDSA.KeyPair

    private class EdPublicKey(
        val key: SwiftEdDsaPublicKey,
    ) : EdDSA.PublicKey {
        override fun encodeToByteArrayBlocking(format: EdDSA.PublicKey.Format): ByteArray = when (format) {
            EdDSA.PublicKey.Format.RAW -> key.rawRepresentation().toByteArray()
            EdDSA.PublicKey.Format.DER -> wrapSubjectPublicKeyInfo(
                UnknownKeyAlgorithmIdentifier(ObjectIdentifier.Ed25519),
                key.rawRepresentation().toByteArray()
            )
            EdDSA.PublicKey.Format.PEM -> wrapPem(PemLabel.PublicKey, encodeToByteArrayBlocking(EdDSA.PublicKey.Format.DER))
            else                       -> error("$format is not supported by CryptoKit EdDSA")
        }

        override fun signatureVerifier(): SignatureVerifier = object : SignatureVerifier {
            override fun createVerifyFunction(): VerifyFunction =
                AccumulatingVerifyFunction { data, signature ->
                    val isValid = data.useNSData { dataNs ->
                        signature.useNSData { sigNs ->
                            key.verifyWithSignature(sigNs, message = dataNs)
                        }
                    }
                    if (isValid) null else "Signature verification failed"
                }
        }
    }

    private class EdPrivateKey(
        val key: SwiftEdDsaPrivateKey,
    ) : EdDSA.PrivateKey {
        override fun getPublicKeyBlocking(): EdDSA.PublicKey = EdPublicKey(key.publicKey())

        override fun encodeToByteArrayBlocking(format: EdDSA.PrivateKey.Format): ByteArray = when (format) {
            EdDSA.PrivateKey.Format.RAW -> key.rawRepresentation().toByteArray()
            EdDSA.PrivateKey.Format.DER -> {
                // EdDSA/XDH private keys in PKCS#8 need to be wrapped in OCTET STRING
                val rawKey = key.rawRepresentation().toByteArray()
                val wrappedKey = Der.encodeToByteArray(ByteArraySerializer(), rawKey)
                wrapPrivateKeyInfo(0, UnknownKeyAlgorithmIdentifier(ObjectIdentifier.Ed25519), wrappedKey)
            }
            EdDSA.PrivateKey.Format.PEM -> wrapPem(PemLabel.PrivateKey, encodeToByteArrayBlocking(EdDSA.PrivateKey.Format.DER))
            else                        -> error("$format is not supported by CryptoKit EdDSA")
        }

        override fun signatureGenerator(): SignatureGenerator = object : SignatureGenerator {
            override fun createSignFunction(): SignFunction =
                AccumulatingSignFunction { data ->
                    swiftTry { error -> data.useNSData { key.signWithMessage(it, error) } }.toByteArray()
                }

            override fun generateSignatureBlocking(data: ByteArray): ByteArray =
                swiftTry { error -> data.useNSData { key.signWithMessage(it, error) } }.toByteArray()
        }
    }
}
