/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.cipher.*
import dev.whyoleg.cryptography.operations.signature.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.materials.*
import dev.whyoleg.cryptography.providers.jdk.operations.*
import javax.crypto.spec.*

internal class JdkAesCbc(
    private val state: JdkCryptographyState,
) : AES.CBC {
    private val keyWrapper: (JSecretKey) -> AES.CBC.Key = { key ->
        object : AES.CBC.Key, JdkEncodableKey<AES.Key.Format>(key) {
            override fun cipher(padding: Boolean): AES.IvCipher = AesCbcCipher(state, key, padding)
            override fun encodeToBlocking(format: AES.Key.Format): ByteArray = when (format) {
                AES.Key.Format.JWK -> error("$format is not supported")
                AES.Key.Format.RAW -> encodeToRaw()
            }
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
) : AES.IvCipher {
    private val cipher = state.cipher(
        when {
            padding -> "AES/CBC/PKCS5Padding"
            else    -> "AES/CBC/NoPadding"
        }
    )

    override fun encryptBlocking(plaintextInput: ByteArray): ByteArray {
        val iv = ByteArray(ivSizeBytes).also(state.secureRandom::nextBytes)
        return iv + encryptBlocking(iv, plaintextInput)
    }

    @DelicateCryptographyApi
    override fun encryptBlocking(iv: ByteArray, plaintextInput: ByteArray): ByteArray = cipher.use { cipher ->
        cipher.init(JCipher.ENCRYPT_MODE, key, IvParameterSpec(iv), state.secureRandom)
        cipher.doFinal(plaintextInput)
    }

    override fun decryptBlocking(ciphertextInput: ByteArray): ByteArray = cipher.use { cipher ->
        cipher.init(JCipher.DECRYPT_MODE, key, IvParameterSpec(ciphertextInput, 0, ivSizeBytes), state.secureRandom)
        cipher.doFinal(ciphertextInput, ivSizeBytes, ciphertextInput.size - ivSizeBytes)
    }

    @DelicateCryptographyApi
    override fun decryptBlocking(iv: ByteArray, ciphertextInput: ByteArray): ByteArray = cipher.use { cipher ->
        cipher.init(JCipher.DECRYPT_MODE, key, IvParameterSpec(iv), state.secureRandom)
        cipher.doFinal(ciphertextInput)
    }
}
