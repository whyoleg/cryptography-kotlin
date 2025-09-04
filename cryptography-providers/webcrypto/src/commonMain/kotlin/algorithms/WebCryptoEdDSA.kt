/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*
import dev.whyoleg.cryptography.providers.webcrypto.materials.*
import dev.whyoleg.cryptography.providers.webcrypto.operations.*
import dev.whyoleg.cryptography.providers.base.materials.*
import dev.whyoleg.cryptography.serialization.pem.*

internal object WebCryptoEdDSA : EdDSA {
    private fun curveName(curve: EdDSA.Curve): String = when (curve) {
        EdDSA.Curve.Ed25519 -> "Ed25519"
        EdDSA.Curve.Ed448   -> "Ed448"
    }

    override fun publicKeyDecoder(curve: EdDSA.Curve): KeyDecoder<EdDSA.PublicKey.Format, EdDSA.PublicKey> = WebCryptoKeyDecoder(
        algorithm = Algorithm(curveName(curve)),
        keyProcessor = EdPublicKeyProcessor,
        keyWrapper = WebCryptoKeyWrapper(arrayOf("verify")) { EdDsaPublicKey(it) },
    )

    override fun privateKeyDecoder(curve: EdDSA.Curve): KeyDecoder<EdDSA.PrivateKey.Format, EdDSA.PrivateKey> = WebCryptoKeyDecoder(
        algorithm = Algorithm(curveName(curve)),
        keyProcessor = EdPrivateKeyProcessor,
        keyWrapper = WebCryptoKeyWrapper(arrayOf("sign")) { EdDsaPrivateKey(it) },
    )

    override fun keyPairGenerator(curve: EdDSA.Curve): KeyGenerator<EdDSA.KeyPair> = WebCryptoAsymmetricKeyGenerator(
        algorithm = Algorithm(curveName(curve)),
        keyUsages = arrayOf("verify", "sign"),
        keyPairWrapper = { EdDsaKeyPair(EdDsaPublicKey(it.publicKey), EdDsaPrivateKey(it.privateKey)) },
    )

    private class EdDsaKeyPair(
        override val publicKey: EdDSA.PublicKey,
        override val privateKey: EdDSA.PrivateKey,
    ) : EdDSA.KeyPair

    private class EdDsaPublicKey(
        val publicKey: CryptoKey,
    ) : WebCryptoEncodableKey<EdDSA.PublicKey.Format>(publicKey, EdPublicKeyProcessor), EdDSA.PublicKey {
        override fun signatureVerifier(): SignatureVerifier {
            return WebCryptoSignatureVerifier(Algorithm(publicKey.algorithm.algorithmName), publicKey)
        }
    }

    private class EdDsaPrivateKey(
        val privateKey: CryptoKey,
    ) : WebCryptoEncodableKey<EdDSA.PrivateKey.Format>(privateKey, EdPrivateKeyProcessor), EdDSA.PrivateKey {
        override fun signatureGenerator(): SignatureGenerator {
            return WebCryptoSignatureGenerator(Algorithm(privateKey.algorithm.algorithmName), privateKey)
        }
    }
}

private object EdPublicKeyProcessor : WebCryptoKeyProcessor<EdDSA.PublicKey.Format>() {
    override fun stringFormat(format: EdDSA.PublicKey.Format): String = when (format) {
        EdDSA.PublicKey.Format.JWK -> "jwk"
        EdDSA.PublicKey.Format.RAW -> "raw"
        EdDSA.PublicKey.Format.DER,
        EdDSA.PublicKey.Format.PEM -> "spki"
    }

    override fun beforeDecoding(algorithm: Algorithm, format: EdDSA.PublicKey.Format, key: ByteArray): ByteArray = when (format) {
        EdDSA.PublicKey.Format.JWK -> key
        EdDSA.PublicKey.Format.RAW -> key
        EdDSA.PublicKey.Format.DER -> key
        EdDSA.PublicKey.Format.PEM -> unwrapPem(PemLabel.PublicKey, key)
    }

    override fun afterEncoding(format: EdDSA.PublicKey.Format, key: ByteArray): ByteArray = when (format) {
        EdDSA.PublicKey.Format.JWK -> key
        EdDSA.PublicKey.Format.RAW -> key
        EdDSA.PublicKey.Format.DER -> key
        EdDSA.PublicKey.Format.PEM -> wrapPem(PemLabel.PublicKey, key)
    }
}

private object EdPrivateKeyProcessor : WebCryptoKeyProcessor<EdDSA.PrivateKey.Format>() {
    override fun stringFormat(format: EdDSA.PrivateKey.Format): String = when (format) {
        EdDSA.PrivateKey.Format.JWK,
        EdDSA.PrivateKey.Format.RAW,
        EdDSA.PrivateKey.Format.DER,
        EdDSA.PrivateKey.Format.PEM,
                                  -> "pkcs8"
    }

    override fun beforeDecoding(algorithm: Algorithm, format: EdDSA.PrivateKey.Format, key: ByteArray): ByteArray = when (format) {
        EdDSA.PrivateKey.Format.JWK -> key
        EdDSA.PrivateKey.Format.RAW -> key // treat as already PKCS8 if user passes raw bytes; no wrap
        EdDSA.PrivateKey.Format.DER -> key
        EdDSA.PrivateKey.Format.PEM -> unwrapPem(PemLabel.PrivateKey, key)
    }

    override fun afterEncoding(format: EdDSA.PrivateKey.Format, key: ByteArray): ByteArray = when (format) {
        EdDSA.PrivateKey.Format.JWK -> key
        EdDSA.PrivateKey.Format.RAW -> key
        EdDSA.PrivateKey.Format.DER -> key
        EdDSA.PrivateKey.Format.PEM -> wrapPem(PemLabel.PrivateKey, key)
    }
}
