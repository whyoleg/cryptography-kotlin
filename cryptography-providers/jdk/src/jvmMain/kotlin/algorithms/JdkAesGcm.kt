/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.cipher.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.algorithms.*
import dev.whyoleg.cryptography.providers.jdk.materials.*
import javax.crypto.spec.*

internal class JdkAesGcm(
    private val state: JdkCryptographyState,
) : AES.GCM {
    private val keyWrapper: (JSecretKey) -> AES.GCM.Key = { key ->
        object : AES.GCM.Key, JdkEncodableKey<AES.Key.Format>(key) {
            override fun cipher(tagSize: BinarySize): AuthenticatedCipher = AesGcmCipher(state, key, tagSize)

            override fun encodeToBlocking(format: AES.Key.Format): ByteArray = when (format) {
                AES.Key.Format.JWK -> error("$format is not supported")
                AES.Key.Format.RAW -> encodeToRaw()
            }
        }
    }
    private val keyDecoder = JdkSecretKeyDecoder<AES.Key.Format, _>("AES", keyWrapper)

    override fun keyDecoder(): KeyDecoder<AES.Key.Format, AES.GCM.Key> = keyDecoder
    override fun keyGenerator(keySize: BinarySize): KeyGenerator<AES.GCM.Key> = JdkSecretKeyGenerator(state, "AES", keyWrapper) {
        init(keySize.inBits, state.secureRandom)
    }
}

private const val ivSizeBytes = 12 //bytes for GCM

private class AesGcmCipher(
    private val state: JdkCryptographyState,
    private val key: JSecretKey,
    private val tagSize: BinarySize,
) : AuthenticatedCipher {
    private val cipher = state.cipher("AES/GCM/NoPadding")

    override fun encryptBlocking(plaintext: ByteArray, associatedData: ByteArray?): ByteArray = cipher.use { cipher ->
        val iv = ByteArray(ivSizeBytes).also(state.secureRandom::nextBytes)
        cipher.init(JCipher.ENCRYPT_MODE, key, GCMParameterSpec(tagSize.inBits, iv), state.secureRandom)
        associatedData?.let(cipher::updateAAD)
        iv + cipher.doFinal(plaintext)
    }

    override fun decryptBlocking(ciphertext: ByteArray, associatedData: ByteArray?): ByteArray = cipher.use { cipher ->
        cipher.init(JCipher.DECRYPT_MODE, key, GCMParameterSpec(tagSize.inBits, ciphertext, 0, ivSizeBytes), state.secureRandom)
        associatedData?.let(cipher::updateAAD)
        cipher.doFinal(ciphertext, ivSizeBytes, ciphertext.size - ivSizeBytes)
    }
}
