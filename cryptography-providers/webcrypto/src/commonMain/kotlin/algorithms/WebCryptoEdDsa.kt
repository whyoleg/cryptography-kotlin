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
import dev.whyoleg.cryptography.providers.webcrypto.operations.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.pem.*

internal object WebCryptoEdDsa : EdDSA {
    private val publicKeyWrapper: WebCryptoKeyWrapper<EdDSA.PublicKey> = WebCryptoKeyWrapper(arrayOf("verify"), ::EdDsaPublicKey)
    private val privateKeyWrapper: WebCryptoKeyWrapper<EdDSA.PrivateKey> = WebCryptoKeyWrapper(arrayOf("sign"), ::EdDsaPrivateKey)
    private val keyPairUsages = publicKeyWrapper.usages + privateKeyWrapper.usages
    private val keyPairWrapper: (CryptoKeyPair) -> EdDSA.KeyPair =
        { EdDsaKeyPair(EdDsaPublicKey(it.publicKey), EdDsaPrivateKey(it.privateKey)) }

    override fun publicKeyDecoder(curve: EdDSA.Curve): KeyDecoder<EdDSA.PublicKey.Format, EdDSA.PublicKey> = WebCryptoKeyDecoder(
        algorithm = Algorithm(curve.name),
        keyProcessor = EdPublicKeyProcessor,
        keyWrapper = publicKeyWrapper,
    )

    override fun privateKeyDecoder(curve: EdDSA.Curve): KeyDecoder<EdDSA.PrivateKey.Format, EdDSA.PrivateKey> = WebCryptoKeyDecoder(
        algorithm = Algorithm(curve.name),
        keyProcessor = EdPrivateKeyProcessor,
        keyWrapper = privateKeyWrapper,
    )

    override fun keyPairGenerator(curve: EdDSA.Curve): KeyGenerator<EdDSA.KeyPair> = WebCryptoAsymmetricKeyGenerator(
        algorithm = Algorithm(curve.name),
        keyUsages = keyPairUsages,
        keyPairWrapper = keyPairWrapper,
    )

    private class EdDsaKeyPair(
        override val publicKey: EdDSA.PublicKey,
        override val privateKey: EdDSA.PrivateKey,
    ) : EdDSA.KeyPair

    private class EdDsaPublicKey(
        val publicKey: CryptoKey,
    ) : WebCryptoEncodableKey<EdDSA.PublicKey.Format>(publicKey, EdPublicKeyProcessor), EdDSA.PublicKey {
        override fun signatureVerifier(): SignatureVerifier {
            return WebCryptoSignatureVerifier(publicKey.algorithm, publicKey)
        }
    }

    private class EdDsaPrivateKey(
        val privateKey: CryptoKey,
    ) : WebCryptoEncodableKey<EdDSA.PrivateKey.Format>(privateKey, EdPrivateKeyProcessor), EdDSA.PrivateKey {
        override fun signatureGenerator(): SignatureGenerator {
            return WebCryptoSignatureGenerator(privateKey.algorithm, privateKey)
        }

        override suspend fun getPublicKey(): EdDSA.PublicKey = publicKeyWrapper.wrap(
            WebCrypto.reimportPrivateKeyAsPublicKey(
                privateKey = privateKey,
                extractable = true,
                keyUsages = publicKeyWrapper.usages,
            )
        )

        override fun getPublicKeyBlocking(): EdDSA.PublicKey = nonBlocking()
    }
}

private object EdPublicKeyProcessor : WebCryptoKeyProcessor<EdDSA.PublicKey.Format>() {
    override fun stringFormat(format: EdDSA.PublicKey.Format): String = when (format) {
        EdDSA.PublicKey.Format.JWK -> "jwk"
        EdDSA.PublicKey.Format.RAW -> "raw"
        EdDSA.PublicKey.Format.DER,
        EdDSA.PublicKey.Format.PEM,
                                   -> "spki"
    }

    override fun beforeDecoding(algorithm: Algorithm, format: EdDSA.PublicKey.Format, key: ByteArray): ByteArray = when (format) {
        EdDSA.PublicKey.Format.JWK -> key
        EdDSA.PublicKey.Format.RAW -> key
        EdDSA.PublicKey.Format.DER -> key
        EdDSA.PublicKey.Format.PEM -> unwrapPem(PemLabel.PublicKey, key)
    }

    override fun afterEncoding(algorithm: Algorithm, format: EdDSA.PublicKey.Format, key: ByteArray): ByteArray = when (format) {
        EdDSA.PublicKey.Format.JWK -> key
        EdDSA.PublicKey.Format.RAW -> key
        EdDSA.PublicKey.Format.DER -> key
        EdDSA.PublicKey.Format.PEM -> wrapPem(PemLabel.PublicKey, key)
    }
}

private object EdPrivateKeyProcessor : WebCryptoKeyProcessor<EdDSA.PrivateKey.Format>() {
    override fun stringFormat(format: EdDSA.PrivateKey.Format): String = when (format) {
        EdDSA.PrivateKey.Format.JWK -> "jwk"
        EdDSA.PrivateKey.Format.RAW,
        EdDSA.PrivateKey.Format.DER,
        EdDSA.PrivateKey.Format.PEM,
                                    -> "pkcs8"
    }

    override fun beforeDecoding(algorithm: Algorithm, format: EdDSA.PrivateKey.Format, key: ByteArray): ByteArray = when (format) {
        EdDSA.PrivateKey.Format.JWK -> key
        EdDSA.PrivateKey.Format.RAW -> wrapCurvePrivateKeyInfo(0, algorithm.identifier, key)
        EdDSA.PrivateKey.Format.DER -> key
        EdDSA.PrivateKey.Format.PEM -> unwrapPem(PemLabel.PrivateKey, key)
    }

    override fun afterEncoding(algorithm: Algorithm, format: EdDSA.PrivateKey.Format, key: ByteArray): ByteArray = when (format) {
        EdDSA.PrivateKey.Format.JWK -> key
        EdDSA.PrivateKey.Format.RAW -> unwrapCurvePrivateKeyInfo(algorithm.identifier.algorithm, key)
        EdDSA.PrivateKey.Format.DER -> key
        EdDSA.PrivateKey.Format.PEM -> wrapPem(PemLabel.PrivateKey, key)
    }

    private val Algorithm.identifier: AlgorithmIdentifier
        get() = when (algorithmName) {
            "Ed25519" -> Ed25519AlgorithmIdentifier
            "Ed448"   -> Ed448AlgorithmIdentifier
            else      -> error("Unknown EdDSA algorithm: $algorithmName")
        }
}
