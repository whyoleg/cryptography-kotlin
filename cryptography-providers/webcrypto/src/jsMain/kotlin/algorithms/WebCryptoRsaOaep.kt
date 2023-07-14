/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*

import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.cipher.*
import dev.whyoleg.cryptography.providers.webcrypto.*
import dev.whyoleg.cryptography.providers.webcrypto.external.*
import dev.whyoleg.cryptography.providers.webcrypto.materials.*

internal object WebCryptoRsaOaep : RSA.OAEP {
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
    private val publicKeyWrapper: (CryptoKey) -> RSA.OAEP.PublicKey = { key ->
        object : RSA.OAEP.PublicKey, EncodableKey<RSA.PublicKey.Format> by WebCryptoEncodableKey(key, publicKeyFormat) {
            private val encryptor = RsaOaepEncryptor(key)
            override fun encryptor(): AuthenticatedEncryptor = encryptor
        }
    }
    private val privateKeyWrapper: (CryptoKey) -> RSA.OAEP.PrivateKey = { key ->
        object : RSA.OAEP.PrivateKey, EncodableKey<RSA.PrivateKey.Format> by WebCryptoEncodableKey(key, privateKeyFormat) {
            private val decryptor = RsaOaepDecryptor(key)
            override fun decryptor(): AuthenticatedDecryptor = decryptor
        }
    }
    private val keyPairWrapper: (CryptoKeyPair) -> RSA.OAEP.KeyPair = { keyPair ->
        object : RSA.OAEP.KeyPair {
            override val publicKey: RSA.OAEP.PublicKey = publicKeyWrapper(keyPair.publicKey)
            override val privateKey: RSA.OAEP.PrivateKey = privateKeyWrapper(keyPair.privateKey)
        }
    }

    override fun publicKeyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<RSA.PublicKey.Format, RSA.OAEP.PublicKey> =
        WebCryptoKeyDecoder(
            RsaHashedKeyImportAlgorithm("RSA-OAEP", digest.hashAlgorithmName()),
            arrayOf("encrypt"), publicKeyFormat, publicKeyWrapper
        )

    override fun privateKeyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<RSA.PrivateKey.Format, RSA.OAEP.PrivateKey> =
        WebCryptoKeyDecoder(
            RsaHashedKeyImportAlgorithm("RSA-OAEP", digest.hashAlgorithmName()),
            arrayOf("decrypt"), privateKeyFormat, privateKeyWrapper
        )

    override fun keyPairGenerator(
        keySize: BinarySize,
        digest: CryptographyAlgorithmId<Digest>,
        publicExponent: RSA.PublicExponent,
    ): KeyGenerator<RSA.OAEP.KeyPair> = WebCryptoAsymmetricKeyGenerator(
        algorithm = RsaHashedKeyGenerationAlgorithm(
            name = "RSA-OAEP",
            modulusLength = keySize.inBits,
            publicExponent = when (publicExponent) {
                RSA.PublicExponent.F4                                    -> byteArrayOf(0x01, 0x00, 0x01)
                is RSA.PublicExponent.Bytes                              -> publicExponent.value
                is RSA.PublicExponent.Number, is RSA.PublicExponent.Text ->
                    throw IllegalArgumentException("WebCrypto supports only F4 or Bytes public exponent")
            },
            digest.hashAlgorithmName()
        ),
        keyUsages = arrayOf("encrypt", "decrypt"),
        keyPairWrapper = keyPairWrapper
    )
}

private class RsaOaepEncryptor(private val key: CryptoKey) : AuthenticatedEncryptor {

    override suspend fun encrypt(plaintextInput: ByteArray, associatedData: ByteArray?): ByteArray {
        return WebCrypto.subtle.encrypt(
            algorithm = RsaOaepParams(associatedData),
            key = key,
            data = plaintextInput
        ).await().toByteArray()
    }

    override fun encryptBlocking(plaintextInput: ByteArray, associatedData: ByteArray?): ByteArray = nonBlocking()
}

private class RsaOaepDecryptor(private val key: CryptoKey) : AuthenticatedDecryptor {

    override suspend fun decrypt(ciphertextInput: ByteArray, associatedData: ByteArray?): ByteArray {
        return WebCrypto.subtle.decrypt(
            algorithm = RsaOaepParams(associatedData),
            key = key,
            data = ciphertextInput
        ).await().toByteArray()
    }

    override fun decryptBlocking(ciphertextInput: ByteArray, associatedData: ByteArray?): ByteArray = nonBlocking()
}
