/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.algorithms

import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.operations.cipher.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*
import dev.whyoleg.cryptography.providers.webcrypto.materials.*
import dev.whyoleg.cryptography.random.*

internal object WebCryptoAesCbc : WebCryptoAes<AES.CBC.Key>(
    algorithmName = "AES-CBC",
    keyWrapper = WebCryptoKeyWrapper(arrayOf("encrypt", "decrypt"), ::AesCbcKey)
), AES.CBC {
    private class AesCbcKey(key: CryptoKey) : AesKey(key), AES.CBC.Key {
        override fun cipher(padding: Boolean): Cipher {
            require(padding) { "Padding is required in WebCrypto" }
            return AesCbcCipher(key)
        }
    }
}

private const val ivSizeBytes = 16 //bytes for CBC

private class AesCbcCipher(private val key: CryptoKey) : Cipher {

    override suspend fun encrypt(plaintextInput: ByteArray): ByteArray {
        val iv = CryptographyRandom.nextBytes(ivSizeBytes)

        val result = WebCrypto.encrypt(
            algorithm = AesCbcCipherAlgorithm(iv),
            key = key,
            data = plaintextInput
        )

        return iv + result
    }

    override suspend fun decrypt(ciphertextInput: ByteArray): ByteArray {
        require(ciphertextInput.size >= ivSizeBytes) { "Ciphertext is too short" }

        return WebCrypto.decrypt(
            algorithm = AesCbcCipherAlgorithm(ciphertextInput.copyOfRange(0, ivSizeBytes)),
            key = key,
            data = ciphertextInput.copyOfRange(ivSizeBytes, ciphertextInput.size)
        )
    }

    override fun decryptBlocking(ciphertextInput: ByteArray): ByteArray = nonBlocking()
    override fun encryptBlocking(plaintextInput: ByteArray): ByteArray = nonBlocking()
}
