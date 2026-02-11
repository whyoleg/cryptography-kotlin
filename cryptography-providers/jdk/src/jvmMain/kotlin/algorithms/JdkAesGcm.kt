/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.base.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.operations.*
import javax.crypto.spec.*

internal class JdkAesGcm(
    private val state: JdkCryptographyState,
) : AES.GCM, BaseAes<AES.GCM.Key>() {
    override fun wrapKey(rawKey: ByteArray): AES.GCM.Key = AesGcmKey(rawKey)

    private inner class AesGcmKey(rawKey: ByteArray) : AES.GCM.Key, BaseKey(rawKey) {
        private val secretKey: JSecretKey = SecretKeySpec(rawKey, "AES")

        override fun cipher(tagSize: BinarySize): IvAuthenticatedCipher = JdkAesGcmCipher(state, secretKey, tagSize.inBits)
    }
}

private const val defaultIvSize: Int = 12

private class JdkAesGcmCipher(
    private val state: JdkCryptographyState,
    private val key: JSecretKey,
    private val tagSizeBits: Int,
) : BaseIvAuthenticatedCipher {
    private val cipher = state.cipher("AES/GCM/NoPadding")

    override fun createEncryptFunction(associatedData: ByteArray?): CipherFunction {
        val iv = ByteArray(defaultIvSize).also(state.secureRandom::nextBytes)
        return BaseImplicitIvEncryptFunction(iv, createEncryptFunctionWithIv(iv, associatedData))
    }

    override fun createDecryptFunction(associatedData: ByteArray?): CipherFunction {
        return BaseImplicitIvDecryptFunction(defaultIvSize) { iv, startIndex ->
            createDecryptFunctionWithIv(iv, startIndex, defaultIvSize, associatedData)
        }
    }

    override fun createEncryptFunctionWithIv(iv: ByteArray, associatedData: ByteArray?): CipherFunction {
        return JdkCipherFunction(cipher.borrowResource {
            init(JCipher.ENCRYPT_MODE, key, GCMParameterSpec(tagSizeBits, iv), state.secureRandom)
            associatedData?.let(this::updateAAD)
        })
    }

    private fun createDecryptFunctionWithIv(
        iv: ByteArray,
        startIndex: Int,
        ivSize: Int,
        associatedData: ByteArray?,
    ): CipherFunction {
        return JdkCipherFunction(cipher.borrowResource {
            init(JCipher.DECRYPT_MODE, key, GCMParameterSpec(tagSizeBits, iv, startIndex, ivSize), state.secureRandom)
            associatedData?.let(this::updateAAD)
        })
    }

    override fun createDecryptFunctionWithIv(iv: ByteArray, associatedData: ByteArray?): CipherFunction {
        return createDecryptFunctionWithIv(iv, 0, iv.size, associatedData)
    }
}
