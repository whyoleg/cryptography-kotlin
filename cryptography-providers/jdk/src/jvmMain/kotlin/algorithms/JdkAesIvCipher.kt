/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.base.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.operations.*
import javax.crypto.spec.*

internal class JdkAesIvCipher(
    private val state: JdkCryptographyState,
    private val key: JSecretKey,
    private val ivSize: Int,
    algorithm: String,
) : BaseAesIvCipher {
    private val cipher = state.cipher(algorithm)

    override fun createEncryptFunction(): CipherFunction {
        val iv = ByteArray(ivSize).also(state.secureRandom::nextBytes)
        return BaseAesImplicitIvEncryptFunction(iv, createEncryptFunctionWithIv(iv))
    }

    override fun createDecryptFunction(): CipherFunction {
        return BaseAesImplicitIvDecryptFunction(ivSize, ::createDecryptFunctionWithIv)
    }

    override fun createEncryptFunctionWithIv(iv: ByteArray): CipherFunction {
        return JdkCipherFunction(cipher.borrowResource {
            init(JCipher.ENCRYPT_MODE, key, IvParameterSpec(iv), state.secureRandom)
        })
    }

    private fun createDecryptFunctionWithIv(iv: ByteArray, startIndex: Int): CipherFunction {
        return JdkCipherFunction(cipher.borrowResource {
            init(JCipher.DECRYPT_MODE, key, IvParameterSpec(iv, startIndex, ivSize), state.secureRandom)
        })
    }

    override fun createDecryptFunctionWithIv(iv: ByteArray): CipherFunction {
        return createDecryptFunctionWithIv(iv, 0)
    }
}
