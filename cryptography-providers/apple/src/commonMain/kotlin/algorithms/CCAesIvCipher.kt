/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.providers.apple.internal.*
import dev.whyoleg.cryptography.providers.base.operations.*
import platform.CoreCrypto.*

internal class CCAesIvCipher(
    private val algorithm: CCAlgorithm,
    private val mode: CCMode,
    private val padding: CCPadding,
    private val key: ByteArray,
    private val ivSize: Int,
    private val validateCiphertextInputSize: (Int) -> Unit = {},
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

        return CCCipherFunction(
            algorithm = algorithm,
            mode = mode,
            padding = padding,
            operation = kCCEncrypt,
            blockSize = kCCBlockSizeAES128.toInt(),
            key = key,
            iv = iv,
            ivStartIndex = 0
        )
    }

    private fun createDecryptFunctionWithIv(iv: ByteArray, startIndex: Int): CipherFunction {
        require(iv.size - startIndex >= ivSize) { "IV size is wrong" }

        return CCCipherFunction(
            algorithm = algorithm,
            mode = mode,
            padding = padding,
            operation = kCCDecrypt,
            blockSize = kCCBlockSizeAES128.toInt(),
            key = key,
            iv = iv,
            ivStartIndex = startIndex,
            validateFullInputSize = validateCiphertextInputSize
        )
    }

    override fun createDecryptFunctionWithIv(iv: ByteArray): CipherFunction {
        return createDecryptFunctionWithIv(iv, 0)
    }
}
