/*
 * Copyright (c) 2024-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.base.operations.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.operations.*
import kotlinx.cinterop.*

internal class Openssl3AesIvCipher(
    private val cipher: CPointer<EVP_CIPHER>?,
    private val key: ByteArray,
    private val ivSize: Int,
    private val init: (CPointer<EVP_CIPHER_CTX>?) -> Unit = {},
) : BaseAesIvCipher {
    override fun createEncryptFunction(): CipherFunction {
        val iv = CryptographySystem.getDefaultRandom().nextBytes(ivSize)
        return BaseAesImplicitIvEncryptFunction(iv, createEncryptFunctionWithIv(iv))
    }

    override fun createDecryptFunction(): CipherFunction {
        return BaseAesImplicitIvDecryptFunction(ivSize, ::createDecryptFunctionWithIv)
    }

    override fun createEncryptFunctionWithIv(iv: ByteArray): CipherFunction {
        require(iv.size == ivSize) { "IV size is wrong" }

        return EvpCipherFunction(cipher, key, iv, 0, encrypt = true, init)
    }

    private fun createDecryptFunctionWithIv(iv: ByteArray, startIndex: Int): CipherFunction {
        require(iv.size - startIndex >= ivSize) { "IV size is wrong" }

        return EvpCipherFunction(cipher, key, iv, startIndex, encrypt = false, init)
    }

    override fun createDecryptFunctionWithIv(iv: ByteArray): CipherFunction {
        return createDecryptFunctionWithIv(iv, 0)
    }
}
