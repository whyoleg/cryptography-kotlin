package dev.whyoleg.cryptography.jdk.aes

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.aes.*
import dev.whyoleg.cryptography.cipher.*
import dev.whyoleg.cryptography.jdk.*
import javax.crypto.*
import javax.crypto.spec.*
import javax.crypto.Cipher as JdkCipher

private const val ivSizeBytes = 16 //bytes for CBC

internal class AesCbcCipherProvider(
    private val state: JdkCryptographyState,
    private val key: SecretKey,
) : CipherProvider<AES.CBC.CipherParameters>(ENGINE_ID) {
    override fun provideOperation(parameters: AES.CBC.CipherParameters): Cipher = AesCbcCipher(state, key, parameters.padding)
}

internal class AesCbcCipher(
    private val state: JdkCryptographyState,
    private val key: SecretKey,
    padding: Boolean,
) : Cipher {
    private val cipher: ThreadLocal<JdkCipher> = threadLocal {
        state.provider.cipher(
            when {
                padding -> "AES/CBC/PKCS5Padding"
                else    -> "AES/CBC/NoPadding"
            }
        )
    }

    //TODO: set values
    override fun ciphertextSize(plaintextSize: Int): Int = plaintextSize + ivSizeBytes //+ tagSizeBits / 8

    override fun plaintextSize(ciphertextSize: Int): Int = ciphertextSize - ivSizeBytes //- tagSizeBits / 8

    //TODO: we can use single ByteArray for output (generate IV in place, and output it)
    override fun encryptBlocking(plaintextInput: Buffer): Buffer {
        val cipher = cipher.get()
        val iv = ByteArray(ivSizeBytes).also(state.secureRandom::nextBytes)
        cipher.init(JdkCipher.ENCRYPT_MODE, key, IvParameterSpec(iv), state.secureRandom)
        return iv + cipher.doFinal(plaintextInput)
    }

    override fun encryptBlocking(plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer {
        val cipher = cipher.get()
        val iv = ByteArray(ivSizeBytes).also(state.secureRandom::nextBytes)
        cipher.init(JdkCipher.ENCRYPT_MODE, key, IvParameterSpec(iv), state.secureRandom)
        cipher.doFinal(plaintextInput, 0, plaintextInput.size, ciphertextOutput)
        return iv + ciphertextOutput
    }

    override fun decryptBlocking(ciphertextInput: Buffer): Buffer {
        val cipher = cipher.get()
        cipher.init(JdkCipher.DECRYPT_MODE, key, IvParameterSpec(ciphertextInput, 0, ivSizeBytes), state.secureRandom)
        return cipher.doFinal(ciphertextInput, ivSizeBytes, ciphertextInput.size - ivSizeBytes)
    }

    override fun decryptBlocking(ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer {
        val cipher = cipher.get()
        cipher.init(JdkCipher.DECRYPT_MODE, key, IvParameterSpec(ciphertextInput, 0, ivSizeBytes), state.secureRandom)
        cipher.doFinal(ciphertextInput, ivSizeBytes, ciphertextInput.size - ivSizeBytes, plaintextOutput, 0)
        return plaintextOutput
    }

    override suspend fun decrypt(ciphertextInput: Buffer): Buffer {
        TODO("Not yet implemented")
    }

    override suspend fun decrypt(ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer {
        TODO("Not yet implemented")
    }

    override fun decryptFunction(): DecryptFunction {
        TODO("Not yet implemented")
    }

    override suspend fun encrypt(plaintextInput: Buffer): Buffer {
        TODO("Not yet implemented")
    }

    override suspend fun encrypt(plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer {
        TODO("Not yet implemented")
    }

    override fun encryptFunction(): EncryptFunction {
        TODO("Not yet implemented")
    }
}
