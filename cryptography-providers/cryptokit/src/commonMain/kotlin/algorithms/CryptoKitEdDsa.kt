/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.cryptokit.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.base.materials.*
import dev.whyoleg.cryptography.providers.base.operations.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.swift.DwcCryptoKitInterop.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.pem.*

internal object CryptoKitEdDsa : EdDSA {
    override fun publicKeyDecoder(curve: EdDSA.Curve): Decoder<EdDSA.PublicKey.Format, EdDSA.PublicKey> {
        check(curve == EdDSA.Curve.Ed25519) { "CryptoKit supports Ed25519 only" }
        return PublicKeyDecoder
    }

    override fun privateKeyDecoder(curve: EdDSA.Curve): Decoder<EdDSA.PrivateKey.Format, EdDSA.PrivateKey> {
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

    private object PublicKeyDecoder : Decoder<EdDSA.PublicKey.Format, EdDSA.PublicKey> {
        override fun decodeFromByteArrayBlocking(format: EdDSA.PublicKey.Format, bytes: ByteArray): EdDSA.PublicKey {
            val raw = when (format) {
                EdDSA.PublicKey.Format.RAW -> bytes
                EdDSA.PublicKey.Format.DER -> unwrapSubjectPublicKeyInfo(ObjectIdentifier.Ed25519, bytes)
                EdDSA.PublicKey.Format.PEM -> unwrapSubjectPublicKeyInfo(ObjectIdentifier.Ed25519, unwrapPem(PemLabel.PublicKey, bytes))
                EdDSA.PublicKey.Format.JWK -> error("$format is not supported by CryptoKit EdDSA")
            }
            return EdPublicKey(swiftTry { error -> raw.useNSData { SwiftEdDsaPublicKey.decodeRawWithRawRepresentation(it, error) } })
        }
    }

    private object PrivateKeyDecoder : Decoder<EdDSA.PrivateKey.Format, EdDSA.PrivateKey> {
        override fun decodeFromByteArrayBlocking(format: EdDSA.PrivateKey.Format, bytes: ByteArray): EdDSA.PrivateKey {
            val raw = when (format) {
                EdDSA.PrivateKey.Format.RAW -> bytes
                EdDSA.PrivateKey.Format.DER -> unwrapCurvePrivateKeyInfo(ObjectIdentifier.Ed25519, bytes)
                EdDSA.PrivateKey.Format.PEM -> unwrapCurvePrivateKeyInfo(ObjectIdentifier.Ed25519, unwrapPem(PemLabel.PrivateKey, bytes))
                EdDSA.PrivateKey.Format.JWK -> error("$format is not supported by CryptoKit EdDSA")
            }
            return EdPrivateKey(swiftTry { error -> raw.useNSData { SwiftEdDsaPrivateKey.decodeRawWithRawRepresentation(it, error) } })
        }
    }

    private class EdDsaKeyPair(
        override val publicKey: EdDSA.PublicKey,
        override val privateKey: EdDSA.PrivateKey,
    ) : EdDSA.KeyPair

    private class EdPublicKey(val publicKey: SwiftEdDsaPublicKey) : EdDSA.PublicKey, SignatureVerifier {
        private fun encodeToDer(raw: ByteArray): ByteArray =
            wrapSubjectPublicKeyInfo(Ed25519AlgorithmIdentifier, raw)

        override fun encodeToByteArrayBlocking(format: EdDSA.PublicKey.Format): ByteArray {
            val raw = publicKey.rawRepresentation().toByteArray()
            return when (format) {
                EdDSA.PublicKey.Format.RAW -> raw
                EdDSA.PublicKey.Format.DER -> encodeToDer(raw)
                EdDSA.PublicKey.Format.PEM -> wrapPem(PemLabel.PublicKey, encodeToDer(raw))
                EdDSA.PublicKey.Format.JWK -> error("$format is not supported by CryptoKit EdDSA")
            }
        }

        override fun signatureVerifier(): SignatureVerifier = this
        override fun createVerifyFunction(): VerifyFunction = AccumulatingVerifyFunction(::verify)
        private fun verify(data: ByteArray, signature: ByteArray): String? {
            val isValid = data.useNSData { dataNs ->
                signature.useNSData { sigNs ->
                    publicKey.verifyWithSignature(sigNs, message = dataNs)
                }
            }
            return if (isValid) null else "Signature verification failed"
        }
    }

    private class EdPrivateKey(val privateKey: SwiftEdDsaPrivateKey) : EdDSA.PrivateKey, SignatureGenerator {
        override fun getPublicKeyBlocking(): EdDSA.PublicKey = EdPublicKey(privateKey.publicKey())

        private fun encodeToDer(raw: ByteArray): ByteArray =
            wrapCurvePrivateKeyInfo(0, Ed25519AlgorithmIdentifier, raw)

        override fun encodeToByteArrayBlocking(format: EdDSA.PrivateKey.Format): ByteArray {
            val raw = privateKey.rawRepresentation().toByteArray()
            return when (format) {
                EdDSA.PrivateKey.Format.RAW -> raw
                EdDSA.PrivateKey.Format.DER -> encodeToDer(raw)
                EdDSA.PrivateKey.Format.PEM -> wrapPem(PemLabel.PrivateKey, encodeToDer(raw))
                EdDSA.PrivateKey.Format.JWK -> error("$format is not supported by CryptoKit EdDSA")
            }
        }

        override fun signatureGenerator(): SignatureGenerator = this
        override fun createSignFunction(): SignFunction = AccumulatingSignFunction(::sign)
        private fun sign(data: ByteArray): ByteArray {
            return swiftTry { error -> data.useNSData { privateKey.signWithMessage(it, error) } }.toByteArray()
        }
    }
}
