package dev.whyoleg.cryptography.jdk.aes

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.aes.AES.GCM.*
import dev.whyoleg.cryptography.cipher.aead.*
import dev.whyoleg.cryptography.jdk.*
import javax.crypto.*
import javax.crypto.spec.*
import javax.crypto.Cipher as JdkCipher

private const val ivSizeBytes = 12 //bytes for GCM

internal class AesGcmCipherProvider(
    private val state: JdkCryptographyState,
    private val key: SecretKey,
) : AeadBoxCipherProvider<CipherParameters, Box>(ENGINE_ID) {
    override fun provideOperation(parameters: CipherParameters): AeadBoxCipher<Box> = AesGcmCipher(state, key, parameters.tagSize)
}

internal class AesGcmCipher(
    private val state: JdkCryptographyState,
    private val key: SecretKey,
    private val tagSize: BinarySize,
) : AeadBoxCipher<Box> {
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

    override fun encryptBoxBlocking(associatedData: Buffer?, plaintextInput: Buffer): Box {
        val cipher = cipher.get()
        val iv = ByteArray(ivSizeBytes).also(state.secureRandom::nextBytes)
        cipher.init(JdkCipher.ENCRYPT_MODE, key, GCMParameterSpec(tagSize.bits, iv), state.secureRandom)
        associatedData?.let(cipher::updateAAD)
        val ciphertextAndTag = cipher.doFinal(plaintextInput)
        return Box(
            nonce = iv,
            ciphertext = ciphertextAndTag.copyOf(ciphertextAndTag.size - tagSize.bytes),
            tag = ciphertextAndTag.copyOfRange(ciphertextAndTag.size - tagSize.bytes, ciphertextAndTag.size)
        )
    }

    override fun encryptBoxBlocking(associatedData: Buffer?, plaintextInput: Buffer, boxOutput: Box): Box {
        TODO("Not yet implemented")
    }

    override fun encryptFunction(): AeadEncryptFunction {
        TODO("Not yet implemented")
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

    override fun decryptBoxBlocking(associatedData: Buffer?, boxInput: Box): Buffer {
        val cipher = cipher.get()
        cipher.init(JdkCipher.DECRYPT_MODE, key, GCMParameterSpec(tagSize.bits, boxInput.nonce), state.secureRandom)
        associatedData?.let(cipher::updateAAD)
        return cipher.update(boxInput.ciphertext) + cipher.doFinal(boxInput.tag)
    }

    override fun decryptBoxBlocking(associatedData: Buffer?, boxInput: Box, plaintextOutput: Buffer): Buffer {
        TODO("Not yet implemented")
    }

    override fun decryptFunction(): AeadDecryptFunction {
        TODO("Not yet implemented")
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

    override suspend fun decryptBox(associatedData: Buffer?, boxInput: Box): Buffer {
        return state.execute { decryptBoxBlocking(associatedData, boxInput) }
    }

    override suspend fun decryptBox(associatedData: Buffer?, boxInput: Box, plaintextOutput: Buffer): Buffer {
        return state.execute { decryptBoxBlocking(associatedData, boxInput, plaintextOutput) }
    }

    override suspend fun encryptBox(associatedData: Buffer?, plaintextInput: Buffer): Box {
        return state.execute { encryptBoxBlocking(associatedData, plaintextInput) }
    }

    override suspend fun encryptBox(associatedData: Buffer?, plaintextInput: Buffer, boxOutput: Box): Box {
        return state.execute { encryptBoxBlocking(associatedData, plaintextInput, boxOutput) }
    }

}
