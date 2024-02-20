/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.providers.apple.internal.*
import dev.whyoleg.cryptography.random.*
import kotlinx.cinterop.*
import platform.CoreCrypto.*

internal object CCAesCtr : CCAes<AES.CTR.Key>(), AES.CTR {
    override fun wrapKey(key: ByteArray): AES.CTR.Key = AesCtrKey(key)

    private class AesCtrKey(private val key: ByteArray) : AES.CTR.Key {
        override fun cipher(): AES.CTR.Cipher = AesCtrCipher(key)
        override fun encodeToBlocking(format: AES.Key.Format): ByteArray = when (format) {
            AES.Key.Format.RAW -> key.copyOf()
            AES.Key.Format.JWK -> error("JWK is not supported")
        }
    }
}

private const val ivSizeBytes = 16 //bytes for CTR

private class AesCtrCipher(key: ByteArray) : AES.CTR.Cipher {
    private val cipher = CCCipher(
        algorithm = kCCAlgorithmAES,
        mode = kCCModeCTR,
        padding = 0.convert(), // not applicable
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

        return cipher.decrypt(
            iv = ciphertextInput,
            ciphertext = ciphertextInput,
            ciphertextStartIndex = ivSizeBytes
        )
    }

    @DelicateCryptographyApi
    override fun decryptBlocking(iv: ByteArray, ciphertextInput: ByteArray): ByteArray {
        require(iv.size == ivSizeBytes) { "IV size is wrong" }

        return cipher.decrypt(
            iv = iv,
            ciphertext = ciphertextInput,
            ciphertextStartIndex = 0
        )
    }
}
