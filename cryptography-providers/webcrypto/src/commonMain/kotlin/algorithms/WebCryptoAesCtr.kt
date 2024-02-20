/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*
import dev.whyoleg.cryptography.providers.webcrypto.materials.*
import dev.whyoleg.cryptography.random.*

internal object WebCryptoAesCtr : WebCryptoAes<AES.CTR.Key>(
    algorithmName = "AES-CTR",
    keyWrapper = WebCryptoKeyWrapper(arrayOf("encrypt", "decrypt"), ::AesCtrKey)
), AES.CTR {
    private class AesCtrKey(key: CryptoKey) : AesKey(key), AES.CTR.Key {
        override fun cipher(): AES.CTR.Cipher = AesCtrCipher(key)
    }
}

private const val ivSizeBytes = 16 //bytes for CTR

// we use full IV as counter in AesCtrCipherAlgorithm
private const val ivSizeBits = ivSizeBytes * 8 //bits for CTR

private class AesCtrCipher(private val key: CryptoKey) : AES.CTR.Cipher {

    override suspend fun encrypt(plaintextInput: ByteArray): ByteArray {
        val iv = CryptographyRandom.nextBytes(ivSizeBytes)
        return iv + encrypt(iv, plaintextInput)
    }

    @DelicateCryptographyApi
    override suspend fun encrypt(iv: ByteArray, plaintextInput: ByteArray): ByteArray {
        return WebCrypto.encrypt(
            algorithm = AesCtrCipherAlgorithm(iv, ivSizeBits),
            key = key,
            data = plaintextInput
        )
    }

    override suspend fun decrypt(ciphertextInput: ByteArray): ByteArray {
        require(ciphertextInput.size >= ivSizeBytes) { "Ciphertext is too short" }

        return WebCrypto.decrypt(
            algorithm = AesCtrCipherAlgorithm(ciphertextInput.copyOfRange(0, ivSizeBytes), ivSizeBits),
            key = key,
            data = ciphertextInput.copyOfRange(ivSizeBytes, ciphertextInput.size)
        )
    }

    @DelicateCryptographyApi
    override suspend fun decrypt(iv: ByteArray, ciphertextInput: ByteArray): ByteArray {
        require(iv.size == ivSizeBytes) { "IV size is wrong" }

        return WebCrypto.decrypt(
            algorithm = AesCtrCipherAlgorithm(iv, ivSizeBits),
            key = key,
            data = ciphertextInput
        )
    }

    override fun decryptBlocking(ciphertextInput: ByteArray): ByteArray = nonBlocking()
    override fun encryptBlocking(plaintextInput: ByteArray): ByteArray = nonBlocking()
    override fun decryptBlocking(iv: ByteArray, ciphertextInput: ByteArray): ByteArray = nonBlocking()
    override fun encryptBlocking(iv: ByteArray, plaintextInput: ByteArray): ByteArray = nonBlocking()
}
