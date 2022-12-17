package dev.whyoleg.cryptography.jdk.aes

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.cipher.*
import dev.whyoleg.cryptography.jdk.*
import java.security.*
import javax.crypto.*
import javax.crypto.Cipher
import javax.crypto.spec.*

private const val ivSizeBytes = 16 //bytes for CBC

internal class AesCbcCipher(
    padding: Boolean,
    private val key: SecretKey,
    private val secureRandom: SecureRandom,
) : SyncCipher {
    private val cipher: ThreadLocal<Cipher> = threadLocal {
        Cipher.getInstance(
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
        val iv = ByteArray(ivSizeBytes).also(secureRandom::nextBytes)
        cipher.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(iv), secureRandom)
        return iv + cipher.doFinal(plaintextInput)
    }

    override fun encrypt(plaintextInput: Buffer, ciphertextOutput: Buffer): Buffer {
        val cipher = cipher.get()
        val iv = ByteArray(ivSizeBytes).also(secureRandom::nextBytes)
        cipher.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(iv), secureRandom)
        cipher.doFinal(plaintextInput, 0, plaintextInput.size, ciphertextOutput)
        return iv + ciphertextOutput
    }

    override fun decrypt(ciphertextInput: Buffer): Buffer {
        val cipher = cipher.get()
        cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(ciphertextInput, 0, ivSizeBytes))
        return cipher.doFinal(ciphertextInput, ivSizeBytes, ciphertextInput.size - ivSizeBytes)
    }

    override fun decrypt(ciphertextInput: Buffer, plaintextOutput: Buffer): Buffer {
        val cipher = cipher.get()
        cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(ciphertextInput, 0, ivSizeBytes))
        cipher.doFinal(ciphertextInput, ivSizeBytes, ciphertextInput.size - ivSizeBytes, plaintextOutput, 0)
        return plaintextOutput
    }
}
