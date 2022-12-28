package dev.whyoleg.cryptography.jdk.internal.aes

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.symmetric.AES.GCM.*
import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.jdk.internal.*
import dev.whyoleg.cryptography.operations.cipher.aead.*
import javax.crypto.*
import javax.crypto.spec.*
import javax.crypto.Cipher as JdkCipher

private const val ivSizeBytes = 12 //bytes for GCM

internal class AesGcmCipherProvider(
    private val state: JdkCryptographyState,
    private val key: SecretKey,
) : AeadCipherProvider<CipherParameters>() {
    override fun provideOperation(parameters: CipherParameters): AeadCipher = AesGcmCipher(state, key, parameters.tagSize)
}

internal class AesGcmCipher(
    private val state: JdkCryptographyState,
    private val key: SecretKey,
    private val tagSize: BinarySize,
) : AeadCipher {
    private val cipher: ThreadLocal<JdkCipher> = threadLocal { state.provider.cipher("AES/GCM/NoPadding") }

    override fun ciphertextSize(plaintextSize: Int): Int = plaintextSize + ivSizeBytes + tagSize.bytes

    override fun plaintextSize(ciphertextSize: Int): Int = ciphertextSize - ivSizeBytes - tagSize.bytes

    //TODO: we can use single ByteArray for output (generate IV in place, and output it)
    override fun encryptBlocking(associatedData: Buffer?, plaintextInput: Buffer): Buffer {
        val cipher = cipher.get()
        val iv = ByteArray(ivSizeBytes).also(state.secureRandom::nextBytes)
        cipher.init(JdkCipher.ENCRYPT_MODE, key, GCMParameterSpec(tagSize.bits, iv), state.secureRandom)
        associatedData?.let(cipher::updateAAD)
        return iv + cipher.doFinal(plaintextInput)
    }

    override fun encryptBlocking(associatedData: Buffer?, plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer {
        val cipher = cipher.get()
        val iv = ByteArray(ivSizeBytes).also(state.secureRandom::nextBytes)
        cipher.init(JdkCipher.ENCRYPT_MODE, key, GCMParameterSpec(tagSize.bits, iv), state.secureRandom)
        associatedData?.let(cipher::updateAAD)
        cipher.doFinal(plaintextInput, 0, plaintextInput.size, ciphertextOutput)
        return iv + ciphertextOutput
    }

    override fun decryptBlocking(associatedData: Buffer?, ciphertextInput: Buffer): Buffer {
        val cipher = cipher.get()
        cipher.init(JdkCipher.DECRYPT_MODE, key, GCMParameterSpec(tagSize.bits, ciphertextInput, 0, ivSizeBytes), state.secureRandom)
        associatedData?.let(cipher::updateAAD)
        return cipher.doFinal(ciphertextInput, ivSizeBytes, ciphertextInput.size - ivSizeBytes)
    }

    override fun decryptBlocking(associatedData: Buffer?, ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer {
        val cipher = cipher.get()
        cipher.init(JdkCipher.DECRYPT_MODE, key, GCMParameterSpec(tagSize.bits, ciphertextInput, 0, ivSizeBytes), state.secureRandom)
        associatedData?.let(cipher::updateAAD)
        cipher.doFinal(ciphertextInput, ivSizeBytes, ciphertextInput.size - ivSizeBytes, plaintextOutput, 0)
        return plaintextOutput
    }

    override suspend fun decrypt(associatedData: Buffer?, ciphertextInput: Buffer): Buffer {
        return state.execute { decryptBlocking(associatedData, ciphertextInput) }
    }

    override suspend fun decrypt(associatedData: Buffer?, ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer {
        return state.execute { decryptBlocking(associatedData, ciphertextInput, plaintextOutput) }
    }

    override suspend fun encrypt(associatedData: Buffer?, plaintextInput: Buffer): Buffer {
        return state.execute { encryptBlocking(associatedData, plaintextInput) }
    }

    override suspend fun encrypt(associatedData: Buffer?, plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer {
        return state.execute { encryptBlocking(associatedData, plaintextInput, ciphertextOutput) }
    }

}
