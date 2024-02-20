/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.providers.apple.internal.*
import dev.whyoleg.cryptography.random.*
import platform.CoreCrypto.*

internal object CCAesCbc : CCAes<AES.CBC.Key>(), AES.CBC {
    override fun wrapKey(key: ByteArray): AES.CBC.Key = AesCbcKey(key)

    private class AesCbcKey(private val key: ByteArray) : AES.CBC.Key {
        override fun cipher(padding: Boolean): AES.CBC.Cipher = AesCbcCipher(key, padding)
        override fun encodeToBlocking(format: AES.Key.Format): ByteArray = when (format) {
            AES.Key.Format.RAW -> key.copyOf()
            AES.Key.Format.JWK -> error("JWK is not supported")
        }
    }
}

private const val ivSizeBytes = 16 //bytes for CBC
private const val blockSizeBytes = 16 //bytes for CBC

private class AesCbcCipher(key: ByteArray, padding: Boolean) : AES.CBC.Cipher {
    private val cipher = CCCipher(
        algorithm = kCCAlgorithmAES,
        mode = kCCModeCBC,
        padding = if (padding) ccPKCS7Padding else ccNoPadding,
        key = key
    )

    override fun encryptBlocking(plaintextInput: ByteArray): ByteArray {
        val iv = CryptographyRandom.nextBytes(ivSizeBytes)
        return iv + encryptBlocking(iv, plaintextInput)
    }

    @DelicateCryptographyApi
    override fun encryptBlocking(iv: ByteArray, plaintextInput: ByteArray): ByteArray {
        require(iv.size == ivSizeBytes) { "IV size is wrong" }

        return cipher.encrypt(iv, plaintextInput)
    }

    override fun decryptBlocking(ciphertextInput: ByteArray): ByteArray {
        require(ciphertextInput.size >= ivSizeBytes) { "Ciphertext is too short" }
        require(ciphertextInput.size % blockSizeBytes == 0) { "Ciphertext is not padded" }

        return cipher.decrypt(
            iv = ciphertextInput,
            ciphertext = ciphertextInput,
            ciphertextStartIndex = ivSizeBytes
        )
    }

    @DelicateCryptographyApi
    override fun decryptBlocking(iv: ByteArray, ciphertextInput: ByteArray): ByteArray {
        require(iv.size == ivSizeBytes) { "IV size is wrong" }
        require(ciphertextInput.size % blockSizeBytes == 0) { "Ciphertext is not padded" }

        return cipher.decrypt(
            iv = iv,
            ciphertext = ciphertextInput,
            ciphertextStartIndex = 0
        )
    }
}
