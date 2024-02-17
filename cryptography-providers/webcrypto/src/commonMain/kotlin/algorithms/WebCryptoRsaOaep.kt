/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.cipher.*
import dev.whyoleg.cryptography.providers.webcrypto.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*
import dev.whyoleg.cryptography.providers.webcrypto.materials.*

internal object WebCryptoRsaOaep : RSA.OAEP {
    private val publicKeyFormat: (RSA.PublicKey.Format) -> String = {
        when (it) {
            RSA.PublicKey.Format.DER -> "spki"
            RSA.PublicKey.Format.PEM -> "pem-RSA-spki"
            RSA.PublicKey.Format.JWK -> "jwk"
            RSA.PublicKey.Format.DER.PKCS1,
            RSA.PublicKey.Format.PEM.PKCS1,
            -> error("$it format is not supported")
        }
    }
    private val privateKeyFormat: (RSA.PrivateKey.Format) -> String = {
        when (it) {
            RSA.PrivateKey.Format.DER -> "pkcs8"
            RSA.PrivateKey.Format.PEM -> "pem-RSA-pkcs8"
            RSA.PrivateKey.Format.JWK -> "jwk"
            RSA.PrivateKey.Format.DER.PKCS1,
            RSA.PrivateKey.Format.PEM.PKCS1,
            -> error("$it format is not supported")
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
            RsaKeyImportAlgorithm("RSA-OAEP", digest.hashAlgorithmName()),
            arrayOf("encrypt"), publicKeyFormat, publicKeyWrapper
        )

    override fun privateKeyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<RSA.PrivateKey.Format, RSA.OAEP.PrivateKey> =
        WebCryptoKeyDecoder(
            RsaKeyImportAlgorithm("RSA-OAEP", digest.hashAlgorithmName()),
            arrayOf("decrypt"), privateKeyFormat, privateKeyWrapper
        )

    override fun keyPairGenerator(
        keySize: BinarySize,
        digest: CryptographyAlgorithmId<Digest>,
        publicExponent: BigInt,
    ): KeyGenerator<RSA.OAEP.KeyPair> = WebCryptoAsymmetricKeyGenerator(
        algorithm = RsaKeyGenerationAlgorithm(
            name = "RSA-OAEP",
            modulusLength = keySize.inBits,
            publicExponent = publicExponent.encodeToByteArray(),
            hash = digest.hashAlgorithmName()
        ),
        keyUsages = arrayOf("encrypt", "decrypt"),
        keyPairWrapper = keyPairWrapper
    )
}

private class RsaOaepEncryptor(private val key: CryptoKey) : AuthenticatedEncryptor {

    override suspend fun encrypt(plaintextInput: ByteArray, associatedData: ByteArray?): ByteArray {
        return WebCrypto.encrypt(
            algorithm = RsaOaepCipherAlgorithm(associatedData),
            key = key,
            data = plaintextInput
        )
    }

    override fun encryptBlocking(plaintextInput: ByteArray, associatedData: ByteArray?): ByteArray = nonBlocking()
}

private class RsaOaepDecryptor(private val key: CryptoKey) : AuthenticatedDecryptor {

    override suspend fun decrypt(ciphertextInput: ByteArray, associatedData: ByteArray?): ByteArray {
        return WebCrypto.decrypt(
            algorithm = RsaOaepCipherAlgorithm(associatedData),
            key = key,
            data = ciphertextInput
        )
    }

    override fun decryptBlocking(ciphertextInput: ByteArray, associatedData: ByteArray?): ByteArray = nonBlocking()
}
