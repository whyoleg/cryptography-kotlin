/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.operations.cipher.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*
import kotlin.experimental.*
import kotlin.native.ref.*

internal object Openssl3AesEcb : AES.ECB, Openssl3Aes<AES.ECB.Key>() {
    override fun wrapKey(keySize: SymmetricKeySize, key: ByteArray): AES.ECB.Key = AesEcbKey(keySize, key)

    private class AesEcbKey(keySize: SymmetricKeySize, key: ByteArray) : AES.ECB.Key, AesKey(key) {
        private val algorithm = when (keySize) {
            SymmetricKeySize.B128 -> "AES-128-ECB"
            SymmetricKeySize.B192 -> "AES-192-ECB"
            SymmetricKeySize.B256 -> "AES-256-ECB"
            else                  -> error("Unsupported key size")
        }

        override fun cipher(padding: Boolean): Cipher = AesEcbCipher(algorithm, key, padding)
    }
}

private class AesEcbCipher(
    algorithm: String,
    private val key: ByteArray,
    private val padding: Boolean,
) : Cipher {

    private val cipher = EVP_CIPHER_fetch(null, algorithm, null)

    @OptIn(ExperimentalNativeApi::class)
    private val cleaner = createCleaner(cipher, ::EVP_CIPHER_free)

    override fun encryptBlocking(plaintextInput: ByteArray): ByteArray = memScoped {
        val context = EVP_CIPHER_CTX_new()
        try {
            checkError(
                EVP_EncryptInit_ex2(
                    ctx = context,
                    cipher = cipher,
                    key = key.refToU(0),
                    iv = null,
                    params = null
                )
            )
            checkError(EVP_CIPHER_CTX_set_padding(context, if (padding) 1 else 0))

            val blockSize = checkError(EVP_CIPHER_CTX_get_block_size(context))
            val ciphertextOutput = ByteArray(blockSize + plaintextInput.size)

            val outl = alloc<IntVar>()

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

            val produced = producedByUpdate + outl.value
            ciphertextOutput.ensureSizeExactly(produced)
        } finally {
            EVP_CIPHER_CTX_free(context)
        }
    }

    override fun decryptBlocking(ciphertextInput: ByteArray): ByteArray = memScoped {
        val context = EVP_CIPHER_CTX_new()
        try {
            checkError(
                EVP_DecryptInit_ex2(
                    ctx = context,
                    cipher = cipher,
                    key = key.refToU(0),
                    iv = null,
                    params = null
                )
            )
            checkError(EVP_CIPHER_CTX_set_padding(context, if (padding) 1 else 0))

            val blockSize = checkError(EVP_CIPHER_CTX_get_block_size(context))
            val plaintextOutput = ByteArray(blockSize + ciphertextInput.size)

            val outl = alloc<IntVar>()

            checkError(
                EVP_DecryptUpdate(
                    ctx = context,
                    out = plaintextOutput.refToU(0),
                    outl = outl.ptr,
                    `in` = ciphertextInput.safeRefToU(0),
                    inl = ciphertextInput.size
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
