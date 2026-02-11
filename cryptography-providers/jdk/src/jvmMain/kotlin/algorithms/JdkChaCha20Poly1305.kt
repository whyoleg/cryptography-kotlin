/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.base.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import dev.whyoleg.cryptography.providers.jdk.operations.*
import javax.crypto.spec.*

internal class JdkChaCha20Poly1305(
    private val state: JdkCryptographyState,
) : BaseChaCha20Poly1305() {
    override fun wrapKey(rawKey: ByteArray): ChaCha20Poly1305.Key = ChaCha20Poly1305Key(rawKey)

    private inner class ChaCha20Poly1305Key(rawKey: ByteArray) : ChaCha20Poly1305.Key, BaseKey(rawKey) {
        private val secretKey: JSecretKey = SecretKeySpec(rawKey, "ChaCha20")

        override fun cipher(): IvAuthenticatedCipher = JdkChaCha20Poly1305Cipher(state, secretKey)
    }
}

private const val chachaNonceSize: Int = 12

private class JdkChaCha20Poly1305Cipher(
    private val state: JdkCryptographyState,
    private val key: JSecretKey,
) : BaseIvAuthenticatedCipher {
    private val cipher = state.cipher("ChaCha20-Poly1305")

    override fun createEncryptFunction(associatedData: ByteArray?): CipherFunction {
        val iv = ByteArray(chachaNonceSize).also(state.secureRandom::nextBytes)
        return BaseImplicitIvEncryptFunction(iv, createEncryptFunctionWithIv(iv, associatedData))
    }

    override fun createDecryptFunction(associatedData: ByteArray?): CipherFunction {
        return BaseImplicitIvDecryptFunction(chachaNonceSize) { iv: ByteArray, startIndex: Int ->
            createDecryptFunctionWithIv(iv, startIndex, chachaNonceSize, associatedData)
        }
    }

    override fun createEncryptFunctionWithIv(iv: ByteArray, associatedData: ByteArray?): CipherFunction {
        return JdkCipherFunction(cipher.borrowResource {
            init(JCipher.ENCRYPT_MODE, key, IvParameterSpec(iv), state.secureRandom)
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
            init(JCipher.DECRYPT_MODE, key, IvParameterSpec(iv, startIndex, ivSize), state.secureRandom)
            associatedData?.let(this::updateAAD)
        })
    }

    override fun createDecryptFunctionWithIv(iv: ByteArray, associatedData: ByteArray?): CipherFunction {
        return createDecryptFunctionWithIv(iv, 0, iv.size, associatedData)
    }
}
