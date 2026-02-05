/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.cryptokit.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.base.materials.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.swift.DwcCryptoKitInterop.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.pem.*

internal object CryptoKitXdh : XDH {
    override fun publicKeyDecoder(curve: XDH.Curve): Decoder<XDH.PublicKey.Format, XDH.PublicKey> {
        check(curve == XDH.Curve.X25519) { "CryptoKit supports X25519 only" }
        return PublicKeyDecoder
    }

    override fun privateKeyDecoder(curve: XDH.Curve): Decoder<XDH.PrivateKey.Format, XDH.PrivateKey> {
        check(curve == XDH.Curve.X25519) { "CryptoKit supports X25519 only" }
        return PrivateKeyDecoder
    }

    override fun keyPairGenerator(curve: XDH.Curve): KeyGenerator<XDH.KeyPair> {
        check(curve == XDH.Curve.X25519) { "CryptoKit supports X25519 only" }
        return KeyPairGenerator
    }

    private object KeyPairGenerator : KeyGenerator<XDH.KeyPair> {
        override fun generateKeyBlocking(): XDH.KeyPair {
            val privateKey = SwiftXdhPrivateKey.generate()
            return XdhKeyPair(
                publicKey = XdhPublicKey(privateKey.publicKey()),
                privateKey = XdhPrivateKey(privateKey)
            )
        }
    }

    private object PublicKeyDecoder : Decoder<XDH.PublicKey.Format, XDH.PublicKey> {
        override fun decodeFromByteArrayBlocking(format: XDH.PublicKey.Format, bytes: ByteArray): XDH.PublicKey {
            val raw = when (format) {
                XDH.PublicKey.Format.RAW -> bytes
                XDH.PublicKey.Format.DER -> unwrapSubjectPublicKeyInfo(ObjectIdentifier.X25519, bytes)
                XDH.PublicKey.Format.PEM -> unwrapSubjectPublicKeyInfo(ObjectIdentifier.X25519, unwrapPem(PemLabel.PublicKey, bytes))
                else                     -> error("$format is not supported by CryptoKit XDH")
            }
            return XdhPublicKey(swiftTry { error -> raw.useNSData { SwiftXdhPublicKey.decodeRawWithRawRepresentation(it, error) } })
        }
    }

    private object PrivateKeyDecoder : Decoder<XDH.PrivateKey.Format, XDH.PrivateKey> {
        override fun decodeFromByteArrayBlocking(format: XDH.PrivateKey.Format, bytes: ByteArray): XDH.PrivateKey {
            val raw = when (format) {
                XDH.PrivateKey.Format.RAW -> bytes
                XDH.PrivateKey.Format.DER -> unwrapCurvePrivateKeyInfo(ObjectIdentifier.X25519, bytes)
                XDH.PrivateKey.Format.PEM -> unwrapCurvePrivateKeyInfo(ObjectIdentifier.X25519, unwrapPem(PemLabel.PrivateKey, bytes))
                else                      -> error("$format is not supported by CryptoKit XDH")
            }
            return XdhPrivateKey(swiftTry { error -> raw.useNSData { SwiftXdhPrivateKey.decodeRawWithRawRepresentation(it, error) } })
        }
    }

    private class XdhKeyPair(
        override val publicKey: XDH.PublicKey,
        override val privateKey: XDH.PrivateKey,
    ) : XDH.KeyPair

    private class XdhPublicKey(val publicKey: SwiftXdhPublicKey) : XDH.PublicKey, SharedSecretGenerator<XDH.PrivateKey> {
        private fun encodeToDer(raw: ByteArray): ByteArray =
            wrapSubjectPublicKeyInfo(X25519AlgorithmIdentifier, raw)

        override fun encodeToByteArrayBlocking(format: XDH.PublicKey.Format): ByteArray {
            val raw = publicKey.rawRepresentation().toByteArray()
            return when (format) {
                XDH.PublicKey.Format.RAW -> raw
                XDH.PublicKey.Format.DER -> encodeToDer(raw)
                XDH.PublicKey.Format.PEM -> wrapPem(PemLabel.PublicKey, encodeToDer(raw))
                XDH.PublicKey.Format.JWK -> error("$format is not supported by CryptoKit XDH")
            }
        }

        override fun sharedSecretGenerator(): SharedSecretGenerator<XDH.PrivateKey> = this
        override fun generateSharedSecretToByteArrayBlocking(other: XDH.PrivateKey): ByteArray {
            require(other is XdhPrivateKey)
            return deriveSecret(other.privateKey, publicKey)
        }
    }

    private class XdhPrivateKey(val privateKey: SwiftXdhPrivateKey) : XDH.PrivateKey, SharedSecretGenerator<XDH.PublicKey> {
        override fun getPublicKeyBlocking(): XDH.PublicKey = XdhPublicKey(privateKey.publicKey())

        private fun encodeToDer(raw: ByteArray): ByteArray =
            wrapCurvePrivateKeyInfo(0, X25519AlgorithmIdentifier, raw)

        override fun encodeToByteArrayBlocking(format: XDH.PrivateKey.Format): ByteArray {
            val raw = privateKey.rawRepresentation().toByteArray()
            return when (format) {
                XDH.PrivateKey.Format.RAW -> raw
                XDH.PrivateKey.Format.DER -> encodeToDer(raw)
                XDH.PrivateKey.Format.PEM -> wrapPem(PemLabel.PrivateKey, encodeToDer(raw))
                XDH.PrivateKey.Format.JWK -> error("$format is not supported by CryptoKit XDH")
            }
        }

        override fun sharedSecretGenerator(): SharedSecretGenerator<XDH.PublicKey> = this
        override fun generateSharedSecretToByteArrayBlocking(other: XDH.PublicKey): ByteArray {
            require(other is XdhPublicKey)
            return deriveSecret(privateKey, other.publicKey)
        }
    }

    private fun deriveSecret(privateKey: SwiftXdhPrivateKey, publicKey: SwiftXdhPublicKey): ByteArray {
        return swiftTry { error -> privateKey.deriveSecretWith(publicKey, error) }.toByteArray()
    }
}
