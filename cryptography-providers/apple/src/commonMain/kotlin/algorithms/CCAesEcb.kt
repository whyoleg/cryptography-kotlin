/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.apple.internal.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.base.operations.*
import platform.CoreCrypto.*

internal object CCAesEcb : BaseAes<AES.ECB.Key>(), AES.ECB {
    override fun wrapKey(rawKey: ByteArray): AES.ECB.Key = AesEcbKey(rawKey)

    private class AesEcbKey(key: ByteArray) : AES.ECB.Key, BaseKey(key) {
        override fun cipher(padding: Boolean): Cipher = CCAesEcbCipher(key, padding)
    }

    private class CCAesEcbCipher(
        private val key: ByteArray,
        private val padding: Boolean,
    ) : BaseCipher {
        override fun createEncryptFunction(): CipherFunction {
            return CCCipherFunction(
                algorithm = kCCAlgorithmAES,
                mode = kCCModeECB,
                padding = if (padding) ccPKCS7Padding else ccNoPadding,
                operation = kCCEncrypt,
                blockSize = kCCBlockSizeAES128.toInt(),
                key = key,
                iv = null,
                ivStartIndex = 0
            )
        }

        override fun createDecryptFunction(): CipherFunction {
            return CCCipherFunction(
                algorithm = kCCAlgorithmAES,
                mode = kCCModeECB,
                padding = if (padding) ccPKCS7Padding else ccNoPadding,
                operation = kCCDecrypt,
                blockSize = kCCBlockSizeAES128.toInt(),
                key = key,
                iv = null,
                ivStartIndex = 0
            ) {
                require(it % kCCBlockSizeAES128.toInt() == 0) { "Ciphertext is not padded" }
            }
        }
    }
}
