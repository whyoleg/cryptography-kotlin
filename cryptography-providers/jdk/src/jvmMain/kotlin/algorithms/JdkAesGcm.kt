/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.base.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.algorithms.*
import dev.whyoleg.cryptography.providers.jdk.materials.*
import dev.whyoleg.cryptography.providers.jdk.operations.*
import javax.crypto.spec.*

internal class JdkAesGcm(
    private val state: JdkCryptographyState,
) : AES.GCM {
    private val keyWrapper: (JSecretKey) -> AES.GCM.Key = { key -> JdkAesGcmKey(state, key) }
    private val keyDecoder = JdkSecretKeyDecoder<AES.Key.Format, _>("AES", keyWrapper)

    override fun keyDecoder(): KeyDecoder<AES.Key.Format, AES.GCM.Key> = keyDecoder

    override fun keyGenerator(keySize: BinarySize): KeyGenerator<AES.GCM.Key> = JdkSecretKeyGenerator(state, "AES", keyWrapper) {
        init(keySize.inBits, state.secureRandom)
    }
}

private class JdkAesGcmKey(
    private val state: JdkCryptographyState,
    private val key: JSecretKey,
) : AES.GCM.Key, JdkEncodableKey<AES.Key.Format>(key) {
    override fun cipher(tagSize: BinarySize): AES.IvAuthenticatedCipher = JdkAesGcmCipher(state, key, tagSize.inBits)

    override fun encodeToByteArrayBlocking(format: AES.Key.Format): ByteArray = when (format) {
        AES.Key.Format.JWK -> error("$format is not supported")
        AES.Key.Format.RAW -> encodeToRaw()
    }
}

private const val defaultIvSize: Int = 12

private class JdkAesGcmCipher(
    private val state: JdkCryptographyState,
    private val key: JSecretKey,
    private val tagSizeBits: Int,
) : BaseAesIvAuthenticatedCipher {
    private val cipher = state.cipher("AES/GCM/NoPadding")

    override fun createEncryptFunction(associatedData: ByteArray?): CipherFunction {
        val iv = ByteArray(defaultIvSize).also(state.secureRandom::nextBytes)
        return BaseAesImplicitIvEncryptFunction(iv, createEncryptFunctionWithIv(iv, associatedData))
    }

    override fun createDecryptFunction(associatedData: ByteArray?): CipherFunction {
        return BaseAesImplicitIvDecryptFunction(defaultIvSize) { iv, startIndex ->
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
