/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
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

internal object Openssl3AesGcm : AES.GCM, Openssl3Aes<AES.GCM.Key>() {
    override fun wrapKey(keySize: BinarySize, key: ByteArray): AES.GCM.Key = AesGcmKey(keySize, key)

    private class AesGcmKey(keySize: BinarySize, key: ByteArray) : AES.GCM.Key, AesKey(key) {
        private val algorithm = when (keySize) {
            AES.Key.Size.B128 -> "AES-128-GCM"
            AES.Key.Size.B192 -> "AES-192-GCM"
            AES.Key.Size.B256 -> "AES-256-GCM"
            else              -> error("Unsupported key size")
        }

        override fun cipher(tagSize: BinarySize): AES.IvAuthenticatedCipher = AesGcmCipher(algorithm, key, tagSize)
    }
}

private const val ivSizeBytes = 12 //bytes for GCM

private class AesGcmCipher(
    algorithm: String,
    private val key: ByteArray,
    private val tagSize: BinarySize,
) : AES.IvAuthenticatedCipher {

    private val cipher = EVP_CIPHER_fetch(null, algorithm, null)

    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = createCleaner(cipher, ::EVP_CIPHER_free)

    override fun encryptWithIvBlocking(iv: ByteArray, plaintext: ByteArray, associatedData: ByteArray?): ByteArray = memScoped {
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
            val outl = alloc<IntVar>()
            associatedData?.let { ad ->
                checkError(
                    EVP_EncryptUpdate(
                        ctx = context,
                        out = null,
                        outl = outl.ptr,
                        `in` = ad.safeRefToU(0),
                        inl = ad.size
                    )
                )
                check(outl.value == ad.size) { "Unexpected output length: got ${outl.value} expected ${ad.size}" }
            }

            val ciphertextOutput = ByteArray(plaintext.size + tagSize.inBytes)

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
            val producedWithFinal = producedByUpdate + outl.value

            checkError(
                EVP_CIPHER_CTX_ctrl(
                    ctx = context,
                    type = EVP_CTRL_AEAD_GET_TAG,
                    arg = tagSize.inBytes,
                    ptr = ciphertextOutput.refToU(producedWithFinal)
                )
            )
            val produced = producedWithFinal + tagSize.inBytes
            ciphertextOutput.ensureSizeExactly(produced)
        } finally {
            EVP_CIPHER_CTX_free(context)
        }
    }

    override fun encryptBlocking(plaintext: ByteArray, associatedData: ByteArray?): ByteArray {
        val iv = ByteArray(ivSizeBytes).also { CryptographyRandom.nextBytes(it) }
        return iv + encryptWithIvBlocking(iv, plaintext, associatedData)
    }

    override fun decryptBlocking(ciphertext: ByteArray, associatedData: ByteArray?): ByteArray {
        require(ciphertext.size >= ivSizeBytes + tagSize.inBytes) { "Ciphertext is too short" }

        return decrypt(
            iv = ciphertext,
            ciphertext = ciphertext,
            ciphertextStartIndex = ivSizeBytes,
            associatedData = associatedData,
        )
    }

    override fun decryptWithIvBlocking(iv: ByteArray, ciphertext: ByteArray, associatedData: ByteArray?): ByteArray {
        require(iv.size == ivSizeBytes) { "IV size is wrong" }
        require(ciphertext.size >= tagSize.inBytes) { "Ciphertext is too short" }

        return decrypt(
            iv = iv,
            ciphertext = ciphertext,
            ciphertextStartIndex = 0,
            associatedData = associatedData,
        )
    }

    private fun decrypt(iv: ByteArray, ciphertext: ByteArray, ciphertextStartIndex: Int, associatedData: ByteArray?): ByteArray = memScoped {
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
            val outl = alloc<IntVar>()

            associatedData?.let { ad ->
                checkError(
                    EVP_DecryptUpdate(
                        ctx = context,
                        out = null,
                        outl = outl.ptr,
                        `in` = ad.safeRefToU(0),
                        inl = ad.size
                    )
                )
                check(outl.value == ad.size) { "Unexpected output length: got ${outl.value} expected ${ad.size}" }
            }

            val plaintextOutput = ByteArray(ciphertext.size - ciphertextStartIndex - tagSize.inBytes)
            checkError(
                EVP_DecryptUpdate(
                    ctx = context,
                    out = plaintextOutput.safeRefToU(0),
                    outl = outl.ptr,
                    `in` = ciphertext.refToU(ciphertextStartIndex),
                    inl = ciphertext.size - ciphertextStartIndex - tagSize.inBytes
                )
            )
            if (plaintextOutput.isEmpty()) check(outl.value == 0) { "Unexpected output length: got ${outl.value} expected 0" }

            val producedByUpdate = outl.value

            checkError(
                EVP_CIPHER_CTX_ctrl(
                    ctx = context,
                    type = EVP_CTRL_AEAD_SET_TAG,
                    arg = tagSize.inBytes,
                    ptr = ciphertext.refToU(ciphertext.size - tagSize.inBytes)
                )
            )

            checkError(
                EVP_DecryptFinal_ex(
                    ctx = context,
                    outm = plaintextOutput.safeRefToU(producedByUpdate),
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
