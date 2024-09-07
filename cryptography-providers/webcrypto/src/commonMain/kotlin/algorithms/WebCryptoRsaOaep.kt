/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.algorithms

import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*
import dev.whyoleg.cryptography.providers.webcrypto.materials.*

internal object WebCryptoRsaOaep : WebCryptoRsa<RSA.OAEP.PublicKey, RSA.OAEP.PrivateKey, RSA.OAEP.KeyPair>(
    algorithmName = "RSA-OAEP",
    publicKeyWrapper = WebCryptoKeyWrapper(arrayOf("encrypt"), ::RsaOaepPublicKey),
    privateKeyWrapper = WebCryptoKeyWrapper(arrayOf("decrypt"), ::RsaOaepPrivateKey),
    keyPairWrapper = ::RsaOaepKeyPair
), RSA.OAEP {
    private class RsaOaepKeyPair(
        override val publicKey: RSA.OAEP.PublicKey,
        override val privateKey: RSA.OAEP.PrivateKey,
    ) : RSA.OAEP.KeyPair

    private class RsaOaepPublicKey(publicKey: CryptoKey) : RsaPublicKey(publicKey), RSA.OAEP.PublicKey {
        override fun encryptor(): AuthenticatedEncryptor = RsaOaepEncryptor(publicKey)
    }

    private class RsaOaepPrivateKey(privateKey: CryptoKey) : RsaPrivateKey(privateKey), RSA.OAEP.PrivateKey {
        override fun decryptor(): AuthenticatedDecryptor = RsaOaepDecryptor(privateKey)
    }
}

private class RsaOaepEncryptor(private val key: CryptoKey) : AuthenticatedEncryptor {

    override suspend fun encrypt(plaintext: ByteArray, associatedData: ByteArray?): ByteArray {
        return WebCrypto.encrypt(
            algorithm = RsaOaepCipherAlgorithm(associatedData),
            key = key,
            data = plaintext
        )
    }

    override fun encryptBlocking(plaintext: ByteArray, associatedData: ByteArray?): ByteArray = nonBlocking()
}

private class RsaOaepDecryptor(private val key: CryptoKey) : AuthenticatedDecryptor {

    override suspend fun decrypt(ciphertext: ByteArray, associatedData: ByteArray?): ByteArray {
        return WebCrypto.decrypt(
            algorithm = RsaOaepCipherAlgorithm(associatedData),
            key = key,
            data = ciphertext
        )
    }

    override fun decryptBlocking(ciphertext: ByteArray, associatedData: ByteArray?): ByteArray = nonBlocking()
}
