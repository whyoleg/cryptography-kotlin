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

internal object WebCryptoAesGcm : WebCryptoAes<AES.GCM.Key>(
    algorithmName = "AES-GCM",
    keyWrapper = WebCryptoKeyWrapper(arrayOf("encrypt", "decrypt"), ::AesGcmKey)
), AES.GCM {
    private class AesGcmKey(key: CryptoKey) : AesKey(key), AES.GCM.Key {
        override fun cipher(tagSize: BinarySize): IvAuthenticatedCipher = AesGcmCipher(key, tagSize.inBits)
    }
}

private const val ivSizeBytes = 12 // bytes for GCM

private class AesGcmCipher(
    private val key: CryptoKey,
    private val tagSizeBits: Int,
) : IvAuthenticatedCipher {

    override suspend fun encrypt(plaintext: ByteArray, associatedData: ByteArray?): ByteArray {
        val iv = CryptographySystem.getDefaultRandom().nextBytes(ivSizeBytes)
        return iv + encryptWithIv(iv, plaintext, associatedData)
    }

    override suspend fun encryptWithIv(iv: ByteArray, plaintext: ByteArray, associatedData: ByteArray?): ByteArray {
        return WebCrypto.encrypt(
            algorithm = AesGcmCipherAlgorithm(
                additionalData = associatedData,
                iv = iv,
                tagLength = tagSizeBits
            ),
            key = key,
            data = plaintext
        )
    }

    override suspend fun decrypt(ciphertext: ByteArray, associatedData: ByteArray?): ByteArray {
        return decryptWithIv(
            ciphertext.copyOfRange(0, ivSizeBytes),
            ciphertext.copyOfRange(ivSizeBytes, ciphertext.size),
            associatedData
        )
    }

    override suspend fun decryptWithIv(iv: ByteArray, ciphertext: ByteArray, associatedData: ByteArray?): ByteArray {
        return WebCrypto.decrypt(
            algorithm = AesGcmCipherAlgorithm(
                additionalData = associatedData,
                iv = iv,
                tagLength = tagSizeBits
            ),
            key = key,
            data = ciphertext
        )
    }

    override fun decryptWithIvBlocking(iv: ByteArray, ciphertext: ByteArray, associatedData: ByteArray?): ByteArray = nonBlocking()

    override fun encryptWithIvBlocking(iv: ByteArray, plaintext: ByteArray, associatedData: ByteArray?): ByteArray = nonBlocking()

    override fun decryptBlocking(ciphertext: ByteArray, associatedData: ByteArray?): ByteArray = nonBlocking()
    override fun encryptBlocking(plaintext: ByteArray, associatedData: ByteArray?): ByteArray = nonBlocking()

    override fun decryptingSource(ciphertext: RawSource, associatedData: ByteArray?): RawSource = nonBlocking()
    override fun decryptingSink(plaintext: RawSink, associatedData: ByteArray?): RawSink = nonBlocking()
    override fun encryptingSource(plaintext: RawSource, associatedData: ByteArray?): RawSource = nonBlocking()
    override fun encryptingSink(ciphertext: RawSink, associatedData: ByteArray?): RawSink = nonBlocking()

    override fun encryptingSourceWithIv(iv: ByteArray, plaintext: RawSource, associatedData: ByteArray?): RawSource = nonBlocking()
    override fun encryptingSinkWithIv(iv: ByteArray, ciphertext: RawSink, associatedData: ByteArray?): RawSink = nonBlocking()
    override fun decryptingSourceWithIv(iv: ByteArray, plaintext: RawSource, associatedData: ByteArray?): RawSource = nonBlocking()
    override fun decryptingSinkWithIv(iv: ByteArray, ciphertext: RawSink, associatedData: ByteArray?): RawSink = nonBlocking()
}
