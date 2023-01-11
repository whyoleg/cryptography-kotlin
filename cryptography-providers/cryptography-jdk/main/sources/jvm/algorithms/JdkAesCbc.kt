package dev.whyoleg.cryptography.jdk.algorithms

import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.algorithms.symmetric.mac.*
import dev.whyoleg.cryptography.io.*
import dev.whyoleg.cryptography.jdk.*
import dev.whyoleg.cryptography.jdk.materials.*
import dev.whyoleg.cryptography.jdk.operations.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.cipher.*
import dev.whyoleg.cryptography.operations.signature.*
import javax.crypto.spec.*

internal class JdkAesCbc(
    private val state: JdkCryptographyState,
) : AES.CBC {
    private val keyWrapper: (JSecretKey) -> AES.CBC.Key = { key ->
        object : AES.CBC.Key, EncodableKey<AES.Key.Format> by JdkEncodableKey(state, key) {
            override fun cipher(padding: Boolean): Cipher = AesCbcCipher(state, key, padding)
        }
    }
    private val keyDecoder = JdkSecretKeyDecoder<AES.Key.Format, _>(state, "AES", keyWrapper)

    override fun keyDecoder(): KeyDecoder<AES.Key.Format, AES.CBC.Key> = keyDecoder
    override fun keyGenerator(keySize: SymmetricKeySize): KeyGenerator<AES.CBC.Key> = JdkSecretKeyGenerator(state, "AES", keyWrapper) {
        init(keySize.value.bits, state.secureRandom)
    }
}

private const val ivSizeBytes = 16 //bytes for CBC

private class AesCbcCipher(
    private val state: JdkCryptographyState,
    private val key: JSecretKey,
    padding: Boolean,
) : Cipher {
    private val cipher = state.cipher(
        when {
            padding -> "AES/CBC/PKCS5Padding"
            else    -> "AES/CBC/NoPadding"
        }
    )

    //TODO: set values
    override fun ciphertextSize(plaintextSize: Int): Int = plaintextSize + ivSizeBytes //+ tagSizeBits / 8

    override fun plaintextSize(ciphertextSize: Int): Int = ciphertextSize - ivSizeBytes //- tagSizeBits / 8

    //TODO: we can use single ByteArray for output (generate IV in place, and output it)
    override fun encryptBlocking(plaintextInput: Buffer): Buffer = cipher.use { cipher ->
        val iv = ByteArray(ivSizeBytes).also(state.secureRandom::nextBytes)
        cipher.init(JCipher.ENCRYPT_MODE, key, IvParameterSpec(iv), state.secureRandom)
        iv + cipher.doFinal(plaintextInput)
    }

    override fun decryptBlocking(ciphertextInput: Buffer): Buffer = cipher.use { cipher ->
        cipher.init(JCipher.DECRYPT_MODE, key, IvParameterSpec(ciphertextInput, 0, ivSizeBytes), state.secureRandom)
        cipher.doFinal(ciphertextInput, ivSizeBytes, ciphertextInput.size - ivSizeBytes)
    }

    override suspend fun decrypt(ciphertextInput: Buffer): Buffer {
        return state.execute { decryptBlocking(ciphertextInput) }
    }

    override suspend fun encrypt(plaintextInput: Buffer): Buffer {
        return state.execute { encryptBlocking(plaintextInput) }
    }
}
