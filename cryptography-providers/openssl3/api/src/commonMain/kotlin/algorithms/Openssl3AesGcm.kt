/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.openssl3.internal.*
import dev.whyoleg.cryptography.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.operations.cipher.*
import dev.whyoleg.cryptography.random.*
import kotlinx.cinterop.*
import kotlin.experimental.*
import kotlin.native.ref.*

internal object Openssl3AesGcm : AES.GCM, Openssl3Aes<AES.GCM.Key>() {
    override fun wrapKey(keySize: SymmetricKeySize, key: ByteArray): AES.GCM.Key = AesGcmKey(keySize, key)

    private class AesGcmKey(keySize: SymmetricKeySize, key: ByteArray) : AES.GCM.Key, AesKey(key) {
        private val algorithm = when (keySize) {
            SymmetricKeySize.B128 -> "AES-128-GCM"
            SymmetricKeySize.B192 -> "AES-192-GCM"
            SymmetricKeySize.B256 -> "AES-256-GCM"
            else                  -> error("Unsupported key size")
        }

        override fun cipher(tagSize: BinarySize): AuthenticatedCipher = AesGcmCipher(algorithm, key, tagSize)
    }
}

private const val ivSizeBytes = 12 //bytes for CBC

private class AesGcmCipher(
    algorithm: String,
    private val key: ByteArray,
    private val tagSize: BinarySize,
) : AuthenticatedCipher {

    private val cipher = EVP_CIPHER_fetch(null, algorithm, null)

    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = createCleaner(cipher, ::EVP_CIPHER_free)

    override fun encryptBlocking(plaintextInput: ByteArray, associatedData: ByteArray?): ByteArray = memScoped {
        val context = EVP_CIPHER_CTX_new()
        try {
            val iv = ByteArray(ivSizeBytes).also { CryptographyRandom.nextBytes(it) }

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

            val ciphertextOutput = ByteArray(plaintextInput.size + tagSize.inBytes)

            checkError(
                EVP_EncryptUpdate(
                    ctx = context,
                    out = ciphertextOutput.refToU(0),
                    outl = outl.ptr,
                    `in` = plaintextInput.safeRefToU(0),
                    inl = plaintextInput.size
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
            iv + ciphertextOutput.ensureSizeExactly(produced)
        } finally {
            EVP_CIPHER_CTX_free(context)
        }
    }

    override fun decryptBlocking(ciphertextInput: ByteArray, associatedData: ByteArray?): ByteArray = memScoped {
        require(ciphertextInput.size >= ivSizeBytes + tagSize.inBytes) { "Ciphertext is too short" }
        val context = EVP_CIPHER_CTX_new()
        try {
            checkError(
                EVP_DecryptInit_ex2(
                    ctx = context,
                    cipher = cipher,
                    key = key.refToU(0),
                    iv = ciphertextInput.refToU(0),
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

            val plaintextOutput = ByteArray(ciphertextInput.size - ivSizeBytes - tagSize.inBytes)
            checkError(
                EVP_DecryptUpdate(
                    ctx = context,
                    out = plaintextOutput.safeRefToU(0),
                    outl = outl.ptr,
                    `in` = ciphertextInput.refToU(ivSizeBytes),
                    inl = ciphertextInput.size - ivSizeBytes - tagSize.inBytes
                )
            )
            if (plaintextOutput.isEmpty()) check(outl.value == 0) { "Unexpected output length: got ${outl.value} expected 0" }

            val producedByUpdate = outl.value

            checkError(
                EVP_CIPHER_CTX_ctrl(
                    ctx = context,
                    type = EVP_CTRL_AEAD_SET_TAG,
                    arg = tagSize.inBytes,
                    ptr = ciphertextInput.refToU(ciphertextInput.size - tagSize.inBytes)
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
