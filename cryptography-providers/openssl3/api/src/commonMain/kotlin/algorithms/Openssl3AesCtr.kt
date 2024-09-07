/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.random.*
import kotlinx.cinterop.*
import kotlin.experimental.*
import kotlin.native.ref.*

internal object Openssl3AesCtr : AES.CTR, Openssl3Aes<AES.CTR.Key>() {
    override fun wrapKey(keySize: BinarySize, key: ByteArray): AES.CTR.Key = AesCtrKey(keySize, key)

    private class AesCtrKey(keySize: BinarySize, key: ByteArray) : AES.CTR.Key, AesKey(key) {
        private val algorithm = when (keySize) {
            AES.Key.Size.B128 -> "AES-128-CTR"
            AES.Key.Size.B192 -> "AES-192-CTR"
            AES.Key.Size.B256 -> "AES-256-CTR"
            else              -> error("Unsupported key size")
        }

        override fun cipher(): AES.IvCipher = AesCtrCipher(algorithm, key)
    }
}

private const val ivSizeBytes = 16 //bytes for CTR

private class AesCtrCipher(
    algorithm: String,
    private val key: ByteArray,
) : AES.IvCipher {

    private val cipher = EVP_CIPHER_fetch(null, algorithm, null)

    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = createCleaner(cipher, ::EVP_CIPHER_free)

    override fun encryptBlocking(plaintext: ByteArray): ByteArray {
        val iv = CryptographyRandom.nextBytes(ivSizeBytes)
        return iv + encryptBlocking(iv, plaintext)
    }

    @DelicateCryptographyApi
    override fun encryptBlocking(iv: ByteArray, plaintext: ByteArray): ByteArray = memScoped {
        require(iv.size == ivSizeBytes) { "IV size is wrong" }

        val context = EVP_CIPHER_CTX_new()
        try {
            checkError(
                EVP_EncryptInit_ex2(
                    ctx = context,
                    cipher = cipher,
                    key = key.refToU(0),
                    iv = iv.refToU(0),
                    params = null
                )
            )

            val blockSize = checkError(EVP_CIPHER_CTX_get_block_size(context))
            val ciphertextOutput = ByteArray(blockSize + plaintext.size)

            val outl = alloc<IntVar>()

            checkError(
                EVP_EncryptUpdate(
                    ctx = context,
                    out = ciphertextOutput.refToU(0),
                    outl = outl.ptr,
                    `in` = plaintext.safeRefToU(0),
                    inl = plaintext.size
                )
            )

            val producedByUpdate = outl.value

            checkError(
                EVP_EncryptFinal_ex(
                    ctx = context,
                    out = ciphertextOutput.refToU(outl.value),
                    outl = outl.ptr
                )
            )

            val produced = producedByUpdate + outl.value
            ciphertextOutput.ensureSizeExactly(produced)
        } finally {
            EVP_CIPHER_CTX_free(context)
        }
    }

    override fun decryptBlocking(ciphertext: ByteArray): ByteArray {
        require(ciphertext.size >= ivSizeBytes) { "Ciphertext is too short" }

        return decrypt(
            iv = ciphertext,
            ciphertext = ciphertext,
            ciphertextStartIndex = ivSizeBytes,
        )
    }

    @DelicateCryptographyApi
    override fun decryptBlocking(iv: ByteArray, ciphertext: ByteArray): ByteArray {
        require(iv.size == ivSizeBytes) { "IV size is wrong" }

        return decrypt(
            iv = iv,
            ciphertext = ciphertext,
            ciphertextStartIndex = 0,
        )
    }

    private fun decrypt(iv: ByteArray, ciphertext: ByteArray, ciphertextStartIndex: Int): ByteArray = memScoped {
        val context = EVP_CIPHER_CTX_new()
        try {
            checkError(
                EVP_DecryptInit_ex2(
                    ctx = context,
                    cipher = cipher,
                    key = key.refToU(0),
                    iv = iv.refToU(0),
                    params = null
                )
            )

            val blockSize = checkError(EVP_CIPHER_CTX_get_block_size(context))
            val plaintextOutput = ByteArray(blockSize + ciphertext.size - ciphertextStartIndex)

            val outl = alloc<IntVar>()

            checkError(
                EVP_DecryptUpdate(
                    ctx = context,
                    out = plaintextOutput.refToU(0),
                    outl = outl.ptr,
                    `in` = ciphertext.safeRefToU(ciphertextStartIndex),
                    inl = ciphertext.size - ciphertextStartIndex
                )
            )

            val producedByUpdate = outl.value

            checkError(
                EVP_DecryptFinal_ex(
                    ctx = context,
                    outm = plaintextOutput.refToU(producedByUpdate),
                    outl = outl.ptr
                )
            )
            val produced = producedByUpdate + outl.value
            plaintextOutput.ensureSizeExactly(produced)
        } finally {
            EVP_CIPHER_CTX_free(context)
        }
    }
}
