/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.materials.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*
import dev.whyoleg.cryptography.providers.webcrypto.materials.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.pem.*

internal object WebCryptoXdh : XDH {
    private val publicKeyWrapper: WebCryptoKeyWrapper<XDH.PublicKey> = WebCryptoKeyWrapper(arrayOf(), ::XdhPublicKey)
    private val privateKeyWrapper: WebCryptoKeyWrapper<XDH.PrivateKey> = WebCryptoKeyWrapper(arrayOf("deriveBits"), ::XdhPrivateKey)
    private val keyPairUsages = publicKeyWrapper.usages + privateKeyWrapper.usages
    private val keyPairWrapper: (CryptoKeyPair) -> XDH.KeyPair = { XdhKeyPair(XdhPublicKey(it.publicKey), XdhPrivateKey(it.privateKey)) }

    override fun publicKeyDecoder(curve: XDH.Curve): KeyDecoder<XDH.PublicKey.Format, XDH.PublicKey> = WebCryptoKeyDecoder(
        algorithm = Algorithm(curve.name),
        keyProcessor = XdhPublicKeyProcessor,
        keyWrapper = publicKeyWrapper,
    )

    override fun privateKeyDecoder(curve: XDH.Curve): KeyDecoder<XDH.PrivateKey.Format, XDH.PrivateKey> = WebCryptoKeyDecoder(
        algorithm = Algorithm(curve.name),
        keyProcessor = XdhPrivateKeyProcessor,
        keyWrapper = privateKeyWrapper,
    )

    override fun keyPairGenerator(curve: XDH.Curve): KeyGenerator<XDH.KeyPair> = WebCryptoAsymmetricKeyGenerator(
        algorithm = Algorithm(curve.name),
        keyUsages = keyPairUsages,
        keyPairWrapper = keyPairWrapper,
    )

    private class XdhKeyPair(
        override val publicKey: XDH.PublicKey,
        override val privateKey: XDH.PrivateKey,
    ) : XDH.KeyPair

    private class XdhPublicKey(
        val publicKey: CryptoKey,
    ) : WebCryptoEncodableKey<XDH.PublicKey.Format>(publicKey, XdhPublicKeyProcessor), XDH.PublicKey,
        SharedSecretGenerator<XDH.PrivateKey> {
        override fun sharedSecretGenerator(): SharedSecretGenerator<XDH.PrivateKey> = this

        override suspend fun generateSharedSecretToByteArray(other: XDH.PrivateKey): ByteArray {
            check(other is XdhPrivateKey)
            val name = publicKey.algorithm.algorithmName
            return WebCrypto.deriveBits(
                algorithm = KeyDeriveAlgorithm(name, publicKey),
                baseKey = other.privateKey,
                length = deriveLengthBits(name)
            )
        }

        override fun generateSharedSecretToByteArrayBlocking(other: XDH.PrivateKey): ByteArray = nonBlocking()
    }

    private class XdhPrivateKey(
        val privateKey: CryptoKey,
    ) : WebCryptoEncodableKey<XDH.PrivateKey.Format>(privateKey, XdhPrivateKeyProcessor), XDH.PrivateKey,
        SharedSecretGenerator<XDH.PublicKey> {
        override fun sharedSecretGenerator(): SharedSecretGenerator<XDH.PublicKey> = this

        override suspend fun getPublicKey(): XDH.PublicKey = publicKeyWrapper.wrap(
            WebCrypto.reimportPrivateKeyAsPublicKey(
                privateKey = privateKey,
                extractable = true,
                keyUsages = publicKeyWrapper.usages,
            )
        )

        override fun getPublicKeyBlocking(): XDH.PublicKey = nonBlocking()

        override suspend fun generateSharedSecretToByteArray(other: XDH.PublicKey): ByteArray {
            check(other is XdhPublicKey)
            val name = privateKey.algorithm.algorithmName
            return WebCrypto.deriveBits(
                algorithm = KeyDeriveAlgorithm(name, other.publicKey),
                baseKey = privateKey,
                length = deriveLengthBits(name)
            )
        }

        override fun generateSharedSecretToByteArrayBlocking(other: XDH.PublicKey): ByteArray = nonBlocking()
    }

    private fun deriveLengthBits(algorithmName: String): Int = when (algorithmName) {
        "X25519" -> 32 * 8
        "X448"   -> 56 * 8
        else     -> error("Unknown XDH algorithm: $algorithmName")
    }
}

private object XdhPublicKeyProcessor : WebCryptoKeyProcessor<XDH.PublicKey.Format>() {
    override fun stringFormat(format: XDH.PublicKey.Format): String = when (format) {
        XDH.PublicKey.Format.JWK -> "jwk"
        XDH.PublicKey.Format.RAW -> "raw"
        XDH.PublicKey.Format.DER,
        XDH.PublicKey.Format.PEM,
                                 -> "spki"
    }

    override fun beforeDecoding(algorithm: Algorithm, format: XDH.PublicKey.Format, key: ByteArray): ByteArray = when (format) {
        XDH.PublicKey.Format.JWK -> key
        XDH.PublicKey.Format.RAW -> key
        XDH.PublicKey.Format.DER -> key
        XDH.PublicKey.Format.PEM -> unwrapPem(PemLabel.PublicKey, key)
    }

    override fun afterEncoding(algorithm: Algorithm, format: XDH.PublicKey.Format, key: ByteArray): ByteArray = when (format) {
        XDH.PublicKey.Format.JWK -> key
        XDH.PublicKey.Format.RAW -> key
        XDH.PublicKey.Format.DER -> key
        XDH.PublicKey.Format.PEM -> wrapPem(PemLabel.PublicKey, key)
    }
}

private object XdhPrivateKeyProcessor : WebCryptoKeyProcessor<XDH.PrivateKey.Format>() {
    override fun stringFormat(format: XDH.PrivateKey.Format): String = when (format) {
        XDH.PrivateKey.Format.JWK -> "jwk"
        XDH.PrivateKey.Format.RAW,
        XDH.PrivateKey.Format.DER,
        XDH.PrivateKey.Format.PEM,
                                  -> "pkcs8"
    }

    override fun beforeDecoding(algorithm: Algorithm, format: XDH.PrivateKey.Format, key: ByteArray): ByteArray = when (format) {
        XDH.PrivateKey.Format.JWK -> key
        XDH.PrivateKey.Format.RAW -> wrapCurvePrivateKeyInfo(0, algorithm.identifier, key)
        XDH.PrivateKey.Format.DER -> key
        XDH.PrivateKey.Format.PEM -> unwrapPem(PemLabel.PrivateKey, key)
    }

    override fun afterEncoding(algorithm: Algorithm, format: XDH.PrivateKey.Format, key: ByteArray): ByteArray = when (format) {
        XDH.PrivateKey.Format.JWK -> key
        XDH.PrivateKey.Format.RAW -> unwrapCurvePrivateKeyInfo(algorithm.identifier.algorithm, key)
        XDH.PrivateKey.Format.DER -> key
        XDH.PrivateKey.Format.PEM -> wrapPem(PemLabel.PrivateKey, key)
    }

    private val Algorithm.identifier: AlgorithmIdentifier
        get() = when (algorithmName) {
            "X25519" -> X25519AlgorithmIdentifier
            "X448"   -> X448AlgorithmIdentifier
            else     -> error("Unknown XDH algorithm: $algorithmName")
        }
}
