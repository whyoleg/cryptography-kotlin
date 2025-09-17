/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*
import dev.whyoleg.cryptography.providers.webcrypto.materials.*
import kotlinx.io.*

internal object WebCryptoAesCbc : WebCryptoAes<AES.CBC.Key>(
    algorithmName = "AES-CBC",
    keyWrapper = WebCryptoKeyWrapper(arrayOf("encrypt", "decrypt"), ::AesCbcKey)
), AES.CBC {
    private class AesCbcKey(key: CryptoKey) : AesKey(key), AES.CBC.Key {
        override fun cipher(padding: Boolean): IvCipher {
            require(padding) { "Padding is required in WebCrypto" }
            return AesCbcCipher(key)
        }
    }
}

private const val ivSizeBytes = 16 //bytes for CBC

private class AesCbcCipher(private val key: CryptoKey) : IvCipher {

    override suspend fun encrypt(plaintext: ByteArray): ByteArray {
        val iv = CryptographySystem.getDefaultRandom().nextBytes(ivSizeBytes)
        return iv + encryptWithIv(iv, plaintext)
    }

    override suspend fun encryptWithIv(iv: ByteArray, plaintext: ByteArray): ByteArray {
        return WebCrypto.encrypt(
            algorithm = AesCbcCipherAlgorithm(iv),
            key = key,
            data = plaintext
        )
    }

    override suspend fun decrypt(ciphertext: ByteArray): ByteArray {
        require(ciphertext.size >= ivSizeBytes) { "Ciphertext is too short" }

        return WebCrypto.decrypt(
            algorithm = AesCbcCipherAlgorithm(ciphertext.copyOfRange(0, ivSizeBytes)),
            key = key,
            data = ciphertext.copyOfRange(ivSizeBytes, ciphertext.size)
        )
    }

    override suspend fun decryptWithIv(iv: ByteArray, ciphertext: ByteArray): ByteArray {
        require(iv.size == ivSizeBytes) { "IV size is wrong" }

        return WebCrypto.decrypt(
            algorithm = AesCbcCipherAlgorithm(iv),
            key = key,
            data = ciphertext
        )
    }

    override fun decryptBlocking(ciphertext: ByteArray): ByteArray = nonBlocking()
    override fun encryptBlocking(plaintext: ByteArray): ByteArray = nonBlocking()
    override fun decryptWithIvBlocking(iv: ByteArray, ciphertext: ByteArray): ByteArray = nonBlocking()
    override fun encryptWithIvBlocking(iv: ByteArray, plaintext: ByteArray): ByteArray = nonBlocking()

    override fun decryptingSource(ciphertext: RawSource): RawSource = nonBlocking()
    override fun decryptingSink(plaintext: RawSink): RawSink = nonBlocking()
    override fun encryptingSource(plaintext: RawSource): RawSource = nonBlocking()
    override fun encryptingSink(ciphertext: RawSink): RawSink = nonBlocking()

    override fun encryptingSourceWithIv(iv: ByteArray, plaintext: RawSource): RawSource = nonBlocking()
    override fun encryptingSinkWithIv(iv: ByteArray, ciphertext: RawSink): RawSink = nonBlocking()
    override fun decryptingSourceWithIv(iv: ByteArray, ciphertext: RawSource): RawSource = nonBlocking()
    override fun decryptingSinkWithIv(iv: ByteArray, plaintext: RawSink): RawSink = nonBlocking()
}
