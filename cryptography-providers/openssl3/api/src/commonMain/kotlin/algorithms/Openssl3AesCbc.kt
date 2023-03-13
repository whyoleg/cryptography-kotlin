package dev.whyoleg.cryptography.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.openssl3.*
import dev.whyoleg.cryptography.openssl3.internal.*
import dev.whyoleg.cryptography.operations.cipher.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.openssl3.internal.cinterop.*
import kotlinx.cinterop.*
import kotlin.native.internal.*

internal object Openssl3AesCbc : AES.CBC, Openssl3Aes<AES.CBC.Key>() {
    override fun wrapKey(keySize: SymmetricKeySize, key: ByteArray): AES.CBC.Key = AesCbcKey(keySize, key)

    private class AesCbcKey(keySize: SymmetricKeySize, key: ByteArray) : AES.CBC.Key, AesKey(key) {
        private val algorithm = when (keySize) {
            SymmetricKeySize.B128 -> "AES-128-CBC"
            SymmetricKeySize.B192 -> "AES-192-CBC"
            SymmetricKeySize.B256 -> "AES-256-CBC"
            else                  -> error("Unsupported key size")
        }

        override fun cipher(padding: Boolean): Cipher = AesCbcCipher(algorithm, key, padding)
    }
}

private const val ivSizeBytes = 16 //bytes for CBC

private class AesCbcCipher(
    algorithm: String,
    private val key: ByteArray,
    private val padding: Boolean,
) : Cipher {

    private val cipher = EVP_CIPHER_fetch(null, algorithm, null)

    @OptIn(ExperimentalStdlibApi::class)
    private val cleaner = createCleaner(cipher, ::EVP_CIPHER_free)

    override fun encryptBlocking(plaintextInput: ByteArray): ByteArray = memScoped {
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
            iv + ciphertextOutput.ensureSizeExactly(produced)
        } finally {
            EVP_CIPHER_CTX_free(context)
        }
    }

    override fun decryptBlocking(ciphertextInput: ByteArray): ByteArray = memScoped {
        require(ciphertextInput.size >= ivSizeBytes) { "Ciphertext is too short" }
//        if (!padding) require(ciphertextInput.size % 16 == 0) { "Ciphertext is not padded" }

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
            checkError(EVP_CIPHER_CTX_set_padding(context, if (padding) 1 else 0))

            val blockSize = checkError(EVP_CIPHER_CTX_get_block_size(context))
            val plaintextOutput = ByteArray(blockSize + ciphertextInput.size - ivSizeBytes)

            val outl = alloc<IntVar>()

            checkError(
                EVP_DecryptUpdate(
                    ctx = context,
                    out = plaintextOutput.refToU(0),
                    outl = outl.ptr,
                    `in` = ciphertextInput.refToU(ivSizeBytes),
                    inl = ciphertextInput.size - ivSizeBytes
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
