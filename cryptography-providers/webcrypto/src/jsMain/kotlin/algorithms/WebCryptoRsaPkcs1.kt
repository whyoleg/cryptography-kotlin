/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.providers.webcrypto.*
import dev.whyoleg.cryptography.providers.webcrypto.external.*
import dev.whyoleg.cryptography.providers.webcrypto.materials.*
import dev.whyoleg.cryptography.providers.webcrypto.operations.*

internal object WebCryptoRsaPkcs1 : RSA.PKCS1 {
    private val publicKeyFormat: (RSA.PublicKey.Format) -> String = {
        when (it) {
            RSA.PublicKey.Format.DER -> "spki"
            RSA.PublicKey.Format.PEM -> "pem-RSA-spki"
            RSA.PublicKey.Format.JWK -> "jwk"
        }
    }
    private val privateKeyFormat: (RSA.PrivateKey.Format) -> String = {
        when (it) {
            RSA.PrivateKey.Format.DER -> "pkcs8"
            RSA.PrivateKey.Format.PEM -> "pem-RSA-pkcs8"
            RSA.PrivateKey.Format.JWK -> "jwk"
        }
    }
    private val publicKeyWrapper: (CryptoKey) -> RSA.PKCS1.PublicKey = { key ->
        object : RSA.PKCS1.PublicKey, EncodableKey<RSA.PublicKey.Format> by WebCryptoEncodableKey(key, publicKeyFormat) {
            override fun signatureVerifier(): SignatureVerifier = WebCryptoSignatureVerifier(
                algorithm = Algorithm("RSASSA-PKCS1-v1_5"),
                key = key
            )
        }
    }
    private val privateKeyWrapper: (CryptoKey) -> RSA.PKCS1.PrivateKey = { key ->
        object : RSA.PKCS1.PrivateKey, EncodableKey<RSA.PrivateKey.Format> by WebCryptoEncodableKey(key, privateKeyFormat) {
            override fun signatureGenerator(): SignatureGenerator = WebCryptoSignatureGenerator(
                algorithm = Algorithm("RSASSA-PKCS1-v1_5"),
                key = key
            )
        }
    }
    private val keyPairWrapper: (CryptoKeyPair) -> RSA.PKCS1.KeyPair = { keyPair ->
        object : RSA.PKCS1.KeyPair {
            override val publicKey: RSA.PKCS1.PublicKey = publicKeyWrapper(keyPair.publicKey)
            override val privateKey: RSA.PKCS1.PrivateKey = privateKeyWrapper(keyPair.privateKey)
        }
    }

    override fun publicKeyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<RSA.PublicKey.Format, RSA.PKCS1.PublicKey> =
        WebCryptoKeyDecoder(
            RsaHashedKeyImportAlgorithm("RSASSA-PKCS1-v1_5", digest.hashAlgorithmName()),
            arrayOf("verify"), publicKeyFormat, publicKeyWrapper
        )

    override fun privateKeyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<RSA.PrivateKey.Format, RSA.PKCS1.PrivateKey> =
        WebCryptoKeyDecoder(
            RsaHashedKeyImportAlgorithm("RSASSA-PKCS1-v1_5", digest.hashAlgorithmName()),
            arrayOf("sign"), privateKeyFormat, privateKeyWrapper
        )

    override fun keyPairGenerator(
        keySize: BinarySize,
        digest: CryptographyAlgorithmId<Digest>,
        publicExponent: RSA.PublicExponent,
    ): KeyGenerator<RSA.PKCS1.KeyPair> = WebCryptoAsymmetricKeyGenerator(
        algorithm = RsaHashedKeyGenerationAlgorithm(
            name = "RSASSA-PKCS1-v1_5",
            modulusLength = keySize.inBits,
            publicExponent = when (publicExponent) {
                RSA.PublicExponent.F4                                    -> byteArrayOf(0x01, 0x00, 0x01)
                is RSA.PublicExponent.Bytes                              -> publicExponent.value
                is RSA.PublicExponent.Number, is RSA.PublicExponent.Text ->
                    throw IllegalArgumentException("WebCrypto supports only F4 or Bytes public exponent")
            },
            digest.hashAlgorithmName()
        ),
        keyUsages = arrayOf("sign", "verify"),
        keyPairWrapper = keyPairWrapper
    )
}
