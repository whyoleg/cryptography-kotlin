package dev.whyoleg.cryptography.jdk.aes

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.cipher.*
import dev.whyoleg.cryptography.jdk.*
import javax.crypto.*
import javax.crypto.spec.*
import javax.crypto.Cipher as JdkCipher

private const val ivSizeBytes = 16 //bytes for CBC

internal class AesCbcCipher(
    private val state: JdkCryptographyState,
    private val key: SecretKey,
    padding: Boolean,
) : SyncCipher {
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
    override fun encrypt(plaintextInput: Buffer): Buffer {
        val cipher = cipher.get()
        val iv = ByteArray(ivSizeBytes).also(state.secureRandom::nextBytes)
        cipher.init(JdkCipher.ENCRYPT_MODE, key, IvParameterSpec(iv), state.secureRandom)
        return iv + cipher.doFinal(plaintextInput)
    }

    override fun encrypt(plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer {
        val cipher = cipher.get()
        val iv = ByteArray(ivSizeBytes).also(state.secureRandom::nextBytes)
        cipher.init(JdkCipher.ENCRYPT_MODE, key, IvParameterSpec(iv), state.secureRandom)
        cipher.doFinal(plaintextInput, 0, plaintextInput.size, ciphertextOutput)
        return iv + ciphertextOutput
    }

    override fun decrypt(ciphertextInput: Buffer): Buffer {
        val cipher = cipher.get()
        cipher.init(JdkCipher.DECRYPT_MODE, key, IvParameterSpec(ciphertextInput, 0, ivSizeBytes), state.secureRandom)
        return cipher.doFinal(ciphertextInput, ivSizeBytes, ciphertextInput.size - ivSizeBytes)
    }

    override fun decrypt(ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer {
        val cipher = cipher.get()
        cipher.init(JdkCipher.DECRYPT_MODE, key, IvParameterSpec(ciphertextInput, 0, ivSizeBytes), state.secureRandom)
        cipher.doFinal(ciphertextInput, ivSizeBytes, ciphertextInput.size - ivSizeBytes, plaintextOutput, 0)
        return plaintextOutput
    }
}
