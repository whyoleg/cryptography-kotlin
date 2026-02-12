/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.operations

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.providers.base.operations.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlinx.cinterop.*

internal class Openssl3IvCipher(
    private val cipher: CPointer<EVP_CIPHER>?,
    private val key: ByteArray,
    private val ivSize: Int,
    private val init: MemScope.(CPointer<EVP_CIPHER_CTX>?) -> Unit = {},
) : BaseIvCipher {
    override fun createEncryptFunction(): CipherFunction {
        val iv = CryptographySystem.getDefaultRandom().nextBytes(ivSize)
        return BaseImplicitIvEncryptFunction(iv, createEncryptFunctionWithIv(iv))
    }

    override fun createDecryptFunction(): CipherFunction {
        return BaseImplicitIvDecryptFunction(ivSize, ::createDecryptFunctionWithIv)
    }

    override fun createEncryptFunctionWithIv(iv: ByteArray): CipherFunction {
        require(iv.size == ivSize) { "IV size is wrong" }

        return EvpCipherFunction(
            cipher = cipher,
            key = key,
            iv = iv,
            ivStartIndex = 0,
            encrypt = true,
            configureContext = init
        )
    }

    private fun createDecryptFunctionWithIv(iv: ByteArray, startIndex: Int): CipherFunction {
        require(iv.size - startIndex >= ivSize) { "IV size is wrong" }

        return EvpCipherFunction(
            cipher = cipher,
            key = key,
            iv = iv,
            ivStartIndex = startIndex,
            encrypt = false,
            configureContext = init
        )
    }

    override fun createDecryptFunctionWithIv(iv: ByteArray): CipherFunction {
        return createDecryptFunctionWithIv(iv, 0)
    }
}
