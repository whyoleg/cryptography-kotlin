package dev.whyoleg.cryptography.jdk.algorithms

import dev.whyoleg.cryptography.algorithms.symmetric.*

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
        object : AES.CBC.Key, EncodableKey<AES.Key.Format> by JdkEncodableKey(key) {
            override fun cipher(padding: Boolean): Cipher = AesCbcCipher(state, key, padding)
        }
    }
    private val keyDecoder = JdkSecretKeyDecoder<AES.Key.Format, _>("AES", keyWrapper)

    override fun keyDecoder(): KeyDecoder<AES.Key.Format, AES.CBC.Key> = keyDecoder
    override fun keyGenerator(keySize: SymmetricKeySize): KeyGenerator<AES.CBC.Key> = JdkSecretKeyGenerator(state, "AES", keyWrapper) {
        init(keySize.value.inBits, state.secureRandom)
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

    override fun encryptBlocking(plaintextInput: ByteArray): ByteArray = cipher.use { cipher ->
        val iv = ByteArray(ivSizeBytes).also(state.secureRandom::nextBytes)
        cipher.init(JCipher.ENCRYPT_MODE, key, IvParameterSpec(iv), state.secureRandom)
        iv + cipher.doFinal(plaintextInput)
    }

    override fun decryptBlocking(ciphertextInput: ByteArray): ByteArray = cipher.use { cipher ->
        cipher.init(JCipher.DECRYPT_MODE, key, IvParameterSpec(ciphertextInput, 0, ivSizeBytes), state.secureRandom)
        cipher.doFinal(ciphertextInput, ivSizeBytes, ciphertextInput.size - ivSizeBytes)
    }
}
