/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import platform.CoreCrypto.*

internal object CCAesCbc : BaseAes<AES.CBC.Key>(), AES.CBC {
    override fun wrapKey(rawKey: ByteArray): AES.CBC.Key = AesCbcKey(rawKey)

    private class AesCbcKey(key: ByteArray) : AES.CBC.Key, BaseKey(key) {
        override fun cipher(padding: Boolean): IvCipher = CCAesIvCipher(
            algorithm = kCCAlgorithmAES,
            mode = kCCModeCBC,
            padding = if (padding) ccPKCS7Padding else ccNoPadding,
            key = key,
            ivSize = 16
        ) {
            require(it % kCCBlockSizeAES128.toInt() == 0) { "Ciphertext is not padded" }
        }
    }
}
