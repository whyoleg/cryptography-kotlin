/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*
import dev.whyoleg.cryptography.providers.webcrypto.materials.*
import dev.whyoleg.cryptography.providers.base.materials.*
import dev.whyoleg.cryptography.serialization.pem.*

internal object WebCryptoXDH : XDH {
    private fun curveName(curve: XDH.Curve): String = when (curve) {
        XDH.Curve.X25519 -> "X25519"
        XDH.Curve.X448   -> "X448"
    }

    override fun publicKeyDecoder(curve: XDH.Curve): KeyDecoder<XDH.PublicKey.Format, XDH.PublicKey> = WebCryptoKeyDecoder(
        algorithm = Algorithm(curveName(curve)),
        keyProcessor = XdhPublicKeyProcessor,
        keyWrapper = WebCryptoKeyWrapper(arrayOf()) { XdhPublicKey(it) },
    )

    override fun privateKeyDecoder(curve: XDH.Curve): KeyDecoder<XDH.PrivateKey.Format, XDH.PrivateKey> = WebCryptoKeyDecoder(
        algorithm = Algorithm(curveName(curve)),
        keyProcessor = XdhPrivateKeyProcessor,
        keyWrapper = WebCryptoKeyWrapper(arrayOf("deriveBits")) { XdhPrivateKey(it) },
    )

    override fun keyPairGenerator(curve: XDH.Curve): KeyGenerator<XDH.KeyPair> = WebCryptoAsymmetricKeyGenerator(
        algorithm = Algorithm(curveName(curve)),
        keyUsages = arrayOf("deriveBits"),
        keyPairWrapper = { XdhKeyPair(XdhPublicKey(it.publicKey), XdhPrivateKey(it.privateKey)) },
    )

    private class XdhKeyPair(
        override val publicKey: XDH.PublicKey,
        override val privateKey: XDH.PrivateKey,
    ) : XDH.KeyPair

    private class XdhPublicKey(
        val publicKey: CryptoKey,
    ) : WebCryptoEncodableKey<XDH.PublicKey.Format>(publicKey, XdhPublicKeyProcessor), XDH.PublicKey, SharedSecretGenerator<XDH.PrivateKey> {
        override fun sharedSecretGenerator(): SharedSecretGenerator<XDH.PrivateKey> = this

        private fun deriveLengthBits(): Int = when (publicKey.algorithm.algorithmName) {
            "X25519" -> 32 * 8
            "X448"   -> 56 * 8
            else      -> error("Unknown XDH algorithm: ${publicKey.algorithm.algorithmName}")
        }

        override suspend fun generateSharedSecretToByteArray(other: XDH.PrivateKey): ByteArray {
            check(other is XdhPrivateKey)
            return WebCrypto.deriveBits(
                algorithm = KeyDeriveAlgorithm(publicKey.algorithm.algorithmName, publicKey),
                baseKey = other.privateKey,
                length = deriveLengthBits()
            )
        }

        override fun generateSharedSecretToByteArrayBlocking(other: XDH.PrivateKey): ByteArray = nonBlocking()
    }

    private class XdhPrivateKey(
        val privateKey: CryptoKey,
    ) : WebCryptoEncodableKey<XDH.PrivateKey.Format>(privateKey, XdhPrivateKeyProcessor), XDH.PrivateKey, SharedSecretGenerator<XDH.PublicKey> {
        override fun sharedSecretGenerator(): SharedSecretGenerator<XDH.PublicKey> = this

        private fun deriveLengthBits(): Int = when (privateKey.algorithm.algorithmName) {
            "X25519" -> 32 * 8
            "X448"   -> 56 * 8
            else      -> error("Unknown XDH algorithm: ${privateKey.algorithm.algorithmName}")
        }

        override suspend fun generateSharedSecretToByteArray(other: XDH.PublicKey): ByteArray {
            check(other is XdhPublicKey)
            return WebCrypto.deriveBits(
                algorithm = KeyDeriveAlgorithm(privateKey.algorithm.algorithmName, other.publicKey),
                baseKey = privateKey,
                length = deriveLengthBits()
            )
        }

        override fun generateSharedSecretToByteArrayBlocking(other: XDH.PublicKey): ByteArray = nonBlocking()
    }
}

private object XdhPublicKeyProcessor : WebCryptoKeyProcessor<XDH.PublicKey.Format>() {
    override fun stringFormat(format: XDH.PublicKey.Format): String = when (format) {
        XDH.PublicKey.Format.JWK -> "jwk"
        XDH.PublicKey.Format.RAW -> "raw"
        XDH.PublicKey.Format.DER,
        XDH.PublicKey.Format.PEM -> "spki"
    }

    override fun beforeDecoding(algorithm: Algorithm, format: XDH.PublicKey.Format, key: ByteArray): ByteArray = when (format) {
        XDH.PublicKey.Format.JWK -> key
        XDH.PublicKey.Format.RAW -> key
        XDH.PublicKey.Format.DER -> key
        XDH.PublicKey.Format.PEM -> unwrapPem(PemLabel.PublicKey, key)
    }

    override fun afterEncoding(format: XDH.PublicKey.Format, key: ByteArray): ByteArray = when (format) {
        XDH.PublicKey.Format.JWK -> key
        XDH.PublicKey.Format.RAW -> key
        XDH.PublicKey.Format.DER -> key
        XDH.PublicKey.Format.PEM -> wrapPem(PemLabel.PublicKey, key)
    }
}

private object XdhPrivateKeyProcessor : WebCryptoKeyProcessor<XDH.PrivateKey.Format>() {
    override fun stringFormat(format: XDH.PrivateKey.Format): String = when (format) {
        XDH.PrivateKey.Format.JWK,
        XDH.PrivateKey.Format.RAW,
        XDH.PrivateKey.Format.DER,
        XDH.PrivateKey.Format.PEM,
                                 -> "pkcs8"
    }

    override fun beforeDecoding(algorithm: Algorithm, format: XDH.PrivateKey.Format, key: ByteArray): ByteArray = when (format) {
        XDH.PrivateKey.Format.JWK -> key
        XDH.PrivateKey.Format.RAW -> key
        XDH.PrivateKey.Format.DER -> key
        XDH.PrivateKey.Format.PEM -> unwrapPem(PemLabel.PrivateKey, key)
    }

    override fun afterEncoding(format: XDH.PrivateKey.Format, key: ByteArray): ByteArray = when (format) {
        XDH.PrivateKey.Format.JWK -> key
        XDH.PrivateKey.Format.RAW -> key
        XDH.PrivateKey.Format.DER -> key
        XDH.PrivateKey.Format.PEM -> wrapPem(PemLabel.PrivateKey, key)
    }
}
