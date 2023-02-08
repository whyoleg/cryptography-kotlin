package dev.whyoleg.cryptography.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.openssl3.*
import dev.whyoleg.cryptography.operations.cipher.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.kcwrapper.libcrypto3.cinterop.*
import kotlinx.cinterop.*
import kotlin.native.internal.*

internal object Openssl3AesCbc : AES.CBC {
    override fun keyDecoder(): KeyDecoder<AES.Key.Format, AES.CBC.Key> = AesCbcKeyDecoder
    override fun keyGenerator(keySize: SymmetricKeySize): KeyGenerator<AES.CBC.Key> = AesCbcKeyGenerator(keySize)
}

private fun requireAesKeySize(keySize: SymmetricKeySize) {
    require(keySize == SymmetricKeySize.B128 || keySize == SymmetricKeySize.B192 || keySize == SymmetricKeySize.B256) {
        "AES key size must be 128, 192 or 256 bits"
    }
}

private object AesCbcKeyDecoder : KeyDecoder<AES.Key.Format, AES.CBC.Key> {
    override fun decodeFromBlocking(format: AES.Key.Format, input: ByteArray): AES.CBC.Key = when (format) {
        AES.Key.Format.RAW -> {
            val keySize = SymmetricKeySize(input.size.bytes)
            requireAesKeySize(keySize)
            AesCbcKey(keySize, input.copyOf())
        }
        AES.Key.Format.JWK -> error("JWK is not supported")
    }
}

private class AesCbcKeyGenerator(
    private val keySize: SymmetricKeySize,
) : KeyGenerator<AES.CBC.Key> {

    init {
        requireAesKeySize(keySize)
    }

    override fun generateKeyBlocking(): AES.CBC.Key {
        val key = CryptographyRandom.nextBytes(keySize.value.inBytes)
        return AesCbcKey(keySize, key)
    }
}

private class AesCbcKey(
    keySize: SymmetricKeySize,
    private val key: ByteArray,
) : AES.CBC.Key {
    private val algorithm = when (keySize) {
        SymmetricKeySize.B128 -> "AES-128-CBC"
        SymmetricKeySize.B192 -> "AES-192-CBC"
        SymmetricKeySize.B256 -> "AES-256-CBC"
        else                  -> error("Unsupported key size")
    }

    override fun cipher(padding: Boolean): Cipher = AesCbcCipher(algorithm, key, padding)

    override fun encodeToBlocking(format: AES.Key.Format): ByteArray = when (format) {
        AES.Key.Format.RAW -> key.copyOf()
        AES.Key.Format.JWK -> error("JWK is not supported")
    }
}

private const val ivSizeBytes = 16 //bytes for GCM

private class AesCbcCipher(
    algorithm: String,
    private val key: ByteArray,
    private val padding: Boolean,
) : Cipher {

    private val cipher = EVP_CIPHER_fetch(null, algorithm, null)

    @OptIn(ExperimentalStdlibApi::class)
    private val cleaner = createCleaner(cipher, ::EVP_CIPHER_free)

    @OptIn(ExperimentalUnsignedTypes::class)
    override fun encryptBlocking(plaintextInput: ByteArray): ByteArray = memScoped {
        val context = EVP_CIPHER_CTX_new()
        try {
            val iv = ByteArray(ivSizeBytes).also { CryptographyRandom.nextBytes(it) }

            checkError(
                EVP_EncryptInit_ex2(
                    ctx = context,
                    cipher = cipher,
                    key = key.asUByteArray().refTo(0),
                    iv = iv.asUByteArray().refTo(0),
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
                    out = ciphertextOutput.asUByteArray().refTo(0),
                    outl = outl.ptr,
                    `in` = plaintextInput.fixEmpty().asUByteArray().refTo(0),
                    inl = plaintextInput.size
                )
            )

            val producedByUpdate = outl.value

            checkError(
                EVP_EncryptFinal_ex(
                    ctx = context,
                    out = ciphertextOutput.asUByteArray().refTo(outl.value),
                    outl = outl.ptr
                )
            )

            val produced = producedByUpdate + outl.value
            iv + when (ciphertextOutput.size) {
                produced -> ciphertextOutput
                else     -> ciphertextOutput.copyOf(produced)
            }
        } finally {
            EVP_CIPHER_CTX_free(context)
        }
    }

    @OptIn(ExperimentalUnsignedTypes::class)
    override fun decryptBlocking(ciphertextInput: ByteArray): ByteArray = memScoped {
        require(ciphertextInput.size >= ivSizeBytes) { "Ciphertext is too short" }
//        if (!padding) require(ciphertextInput.size % 16 == 0) { "Ciphertext is not padded" }

        val context = EVP_CIPHER_CTX_new()
        try {
            checkError(
                EVP_DecryptInit_ex2(
                    ctx = context,
                    cipher = cipher,
                    key = key.asUByteArray().refTo(0),
                    iv = ciphertextInput.asUByteArray().refTo(0),
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
                    out = plaintextOutput.asUByteArray().refTo(0),
                    outl = outl.ptr,
                    `in` = ciphertextInput.asUByteArray().refTo(ivSizeBytes),
                    inl = ciphertextInput.size - ivSizeBytes
                )
            )

            val producedByUpdate = outl.value

            checkError(
                EVP_DecryptFinal_ex(
                    ctx = context,
                    outm = plaintextOutput.asUByteArray().refTo(outl.value),
                    outl = outl.ptr
                )
            )
            val produced = producedByUpdate + outl.value
            when (plaintextOutput.size) {
                produced -> plaintextOutput
                else     -> plaintextOutput.copyOf(produced)
            }
        } finally {
            EVP_CIPHER_CTX_free(context)
        }
    }
}
