package dev.whyoleg.cryptography.jdk.aes

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.cipher.aead.*
import dev.whyoleg.cryptography.jdk.*
import javax.crypto.*
import javax.crypto.spec.*
import javax.crypto.Cipher as JdkCipher

private const val ivSizeBytes = 12 //bytes for GCM

internal class AesGcmCipher(
    private val state: JdkCryptographyState,
    private val key: SecretKey,
    private val tagSizeBits: Int,
) : AeadSyncCipher {
    private val cipher: ThreadLocal<JdkCipher> = threadLocal { state.provider.cipher("AES/GCM/NoPadding") }

    override fun ciphertextSize(plaintextSize: Int): Int = plaintextSize + ivSizeBytes + tagSizeBits / 8

    override fun plaintextSize(ciphertextSize: Int): Int = ciphertextSize - ivSizeBytes - tagSizeBits / 8

    //TODO: we can use single ByteArray for output (generate IV in place, and output it)
    override fun encrypt(associatedData: Buffer?, plaintextInput: Buffer): Buffer {
        val cipher = cipher.get()
        val iv = ByteArray(ivSizeBytes).also(state.secureRandom::nextBytes)
        cipher.init(JdkCipher.ENCRYPT_MODE, key, GCMParameterSpec(tagSizeBits, iv), state.secureRandom)
        associatedData?.let(cipher::updateAAD)
        return iv + cipher.doFinal(plaintextInput)
    }

    override fun encrypt(associatedData: Buffer?, plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer {
        val cipher = cipher.get()
        val iv = ByteArray(ivSizeBytes).also(state.secureRandom::nextBytes)
        cipher.init(JdkCipher.ENCRYPT_MODE, key, GCMParameterSpec(tagSizeBits, iv), state.secureRandom)
        associatedData?.let(cipher::updateAAD)
        cipher.doFinal(plaintextInput, 0, plaintextInput.size, ciphertextOutput)
        return iv + ciphertextOutput
    }

    override fun decrypt(associatedData: Buffer?, ciphertextInput: Buffer): Buffer {
        val cipher = cipher.get()
        cipher.init(JdkCipher.DECRYPT_MODE, key, GCMParameterSpec(tagSizeBits, ciphertextInput, 0, ivSizeBytes), state.secureRandom)
        associatedData?.let(cipher::updateAAD)
        return cipher.doFinal(ciphertextInput, ivSizeBytes, ciphertextInput.size - ivSizeBytes)
    }

    override fun decrypt(associatedData: Buffer?, ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer {
        val cipher = cipher.get()
        cipher.init(JdkCipher.DECRYPT_MODE, key, GCMParameterSpec(tagSizeBits, ciphertextInput, 0, ivSizeBytes), state.secureRandom)
        associatedData?.let(cipher::updateAAD)
        cipher.doFinal(ciphertextInput, ivSizeBytes, ciphertextInput.size - ivSizeBytes, plaintextOutput, 0)
        return plaintextOutput
    }
}
