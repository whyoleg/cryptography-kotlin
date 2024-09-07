/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*
import dev.whyoleg.cryptography.providers.webcrypto.materials.*
import dev.whyoleg.cryptography.random.*

internal object WebCryptoAesGcm : WebCryptoAes<AES.GCM.Key>(
    algorithmName = "AES-GCM",
    keyWrapper = WebCryptoKeyWrapper(arrayOf("encrypt", "decrypt"), ::AesGcmKey)
), AES.GCM {
    private class AesGcmKey(key: CryptoKey) : AesKey(key), AES.GCM.Key {
        override fun cipher(tagSize: BinarySize): AuthenticatedCipher = AesGcmCipher(key, tagSize.inBits)
    }
}

private const val ivSizeBytes = 12 //bytes for GCM

private class AesGcmCipher(
    private val key: CryptoKey,
    private val tagSizeBits: Int,
) : AuthenticatedCipher {

    override suspend fun encrypt(plaintext: ByteArray, associatedData: ByteArray?): ByteArray {
        val iv = CryptographyRandom.nextBytes(ivSizeBytes)

        val ciphertext = WebCrypto.encrypt(
            algorithm = AesGcmCipherAlgorithm(
                additionalData = associatedData,
                iv = iv,
                tagLength = tagSizeBits
            ),
            key = key,
            data = plaintext
        )

        return iv + ciphertext
    }

    override suspend fun decrypt(ciphertext: ByteArray, associatedData: ByteArray?): ByteArray {
        return WebCrypto.decrypt(
            algorithm = AesGcmCipherAlgorithm(
                additionalData = associatedData,
                iv = ciphertext.copyOfRange(0, ivSizeBytes),
                tagLength = tagSizeBits
            ),
            key = key,
            data = ciphertext.copyOfRange(ivSizeBytes, ciphertext.size)
        )
    }

    override fun decryptBlocking(ciphertext: ByteArray, associatedData: ByteArray?): ByteArray = nonBlocking()
    override fun encryptBlocking(plaintext: ByteArray, associatedData: ByteArray?): ByteArray = nonBlocking()
}
