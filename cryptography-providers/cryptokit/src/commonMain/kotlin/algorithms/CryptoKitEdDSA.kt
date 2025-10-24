/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.cryptokit.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.swiftinterop.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.base.materials.*
import dev.whyoleg.cryptography.providers.base.operations.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.pem.*
import kotlinx.cinterop.*
import platform.Foundation.*

internal object CryptoKitEdDSA : EdDSA {
    override fun publicKeyDecoder(curve: EdDSA.Curve): KeyDecoder<EdDSA.PublicKey.Format, EdDSA.PublicKey> {
        check(curve == EdDSA.Curve.Ed25519) { "CryptoKit supports Ed25519 only" }
        return object : KeyDecoder<EdDSA.PublicKey.Format, EdDSA.PublicKey> {
            override fun decodeFromByteArrayBlocking(format: EdDSA.PublicKey.Format, bytes: ByteArray): EdDSA.PublicKey = when (format) {
                EdDSA.PublicKey.Format.RAW -> EdPublicKey(
                    swiftTry<SwiftEdDsaPublicKey> { error -> bytes.useNSData { SwiftEdDsaPublicKey.decodeRawWithRawRepresentation(it, error) } }
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
                else -> error("$format is not supported by CryptoKit EdDSA")
            }
        }
    }

    override fun privateKeyDecoder(curve: EdDSA.Curve): KeyDecoder<EdDSA.PrivateKey.Format, EdDSA.PrivateKey> {
        check(curve == EdDSA.Curve.Ed25519) { "CryptoKit supports Ed25519 only" }
        return object : KeyDecoder<EdDSA.PrivateKey.Format, EdDSA.PrivateKey> {
            override fun decodeFromByteArrayBlocking(format: EdDSA.PrivateKey.Format, bytes: ByteArray): EdDSA.PrivateKey = when (format) {
                EdDSA.PrivateKey.Format.RAW -> EdPrivateKey(
                    swiftTry<SwiftEdDsaPrivateKey> { error -> bytes.useNSData { SwiftEdDsaPrivateKey.decodeRawWithRawRepresentation(it, error) } }
                )
                EdDSA.PrivateKey.Format.DER -> {
                    val raw = unwrapPrivateKeyInfo(ObjectIdentifier.Ed25519, bytes)
                    EdPrivateKey(swiftTry { error -> raw.useNSData { SwiftEdDsaPrivateKey.decodeRawWithRawRepresentation(it, error) } })
                }
                EdDSA.PrivateKey.Format.PEM -> {
                    val der = unwrapPem(PemLabel.PrivateKey, bytes)
                    val raw = unwrapPrivateKeyInfo(ObjectIdentifier.Ed25519, der)
                    EdPrivateKey(swiftTry { error -> raw.useNSData { SwiftEdDsaPrivateKey.decodeRawWithRawRepresentation(it, error) } })
                }
                else -> error("$format is not supported by CryptoKit EdDSA")
            }
        }
    }

    override fun keyPairGenerator(curve: EdDSA.Curve): KeyGenerator<EdDSA.KeyPair> {
        check(curve == EdDSA.Curve.Ed25519) { "CryptoKit supports Ed25519 only" }
        return object : KeyGenerator<EdDSA.KeyPair> {
            override fun generateKeyBlocking(): EdDSA.KeyPair {
                val p = SwiftEdDsaPrivateKey.generate()
                return EdKeyPair(EdPublicKey(p.publicKey()), EdPrivateKey(p))
            }
        }
    }

    private class EdKeyPair(
        override val publicKey: EdDSA.PublicKey,
        override val privateKey: EdDSA.PrivateKey,
    ) : EdDSA.KeyPair

    private class EdPublicKey(
        val key: SwiftEdDsaPublicKey,
    ) : EdDSA.PublicKey {
        override fun encodeToByteArrayBlocking(format: EdDSA.PublicKey.Format): ByteArray = when (format) {
            EdDSA.PublicKey.Format.RAW -> {
                val raw = key.rawRepresentation().toByteArray()
                raw
            }
            EdDSA.PublicKey.Format.DER -> {
                val raw = key.rawRepresentation().toByteArray()
                wrapSubjectPublicKeyInfo(
                    UnknownKeyAlgorithmIdentifier(ObjectIdentifier.Ed25519),
                    raw
                )
            }
            EdDSA.PublicKey.Format.PEM -> {
                val raw = key.rawRepresentation().toByteArray()
                wrapPem(
                    PemLabel.PublicKey,
                    wrapSubjectPublicKeyInfo(
                        UnknownKeyAlgorithmIdentifier(ObjectIdentifier.Ed25519),
                        raw
                    )
                )
            }
            else -> error("$format is not supported by CryptoKit EdDSA")
        }

        override fun signatureVerifier(): SignatureVerifier = object : SignatureVerifier {
            override fun createVerifyFunction(): VerifyFunction =
                AccumulatingVerifyFunction { data, signature, startIndex, endIndex ->
                    val sig = signature.copyOfRange(startIndex, endIndex)
                    val ok = data.useNSData { dataNs -> sig.useNSData { sigNs ->
                        key.verifyWithSignature(sigNs, message = dataNs)
                    } } as Boolean
                    ok
                }
        }
    }

    private class EdPrivateKey(
        val key: SwiftEdDsaPrivateKey,
    ) : EdDSA.PrivateKey {
        override fun encodeToByteArrayBlocking(format: EdDSA.PrivateKey.Format): ByteArray = when (format) {
            EdDSA.PrivateKey.Format.RAW -> {
                val raw = key.rawRepresentation().toByteArray()
                raw
            }
            EdDSA.PrivateKey.Format.DER -> {
                val raw = key.rawRepresentation().toByteArray()
                wrapPrivateKeyInfo(
                    0,
                    UnknownKeyAlgorithmIdentifier(ObjectIdentifier.Ed25519),
                    raw
                )
            }
            EdDSA.PrivateKey.Format.PEM -> {
                val raw = key.rawRepresentation().toByteArray()
                wrapPem(
                    PemLabel.PrivateKey,
                    wrapPrivateKeyInfo(
                        0,
                        UnknownKeyAlgorithmIdentifier(ObjectIdentifier.Ed25519),
                        raw
                    )
                )
            }
            else -> error("$format is not supported by CryptoKit EdDSA")
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
