/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import platform.CoreCrypto.*

internal object CCAesCfb8 : BaseAes<AES.CFB8.Key>(), AES.CFB8 {
    override fun wrapKey(rawKey: ByteArray): AES.CFB8.Key = AesCfb8Key(rawKey)

    private class AesCfb8Key(key: ByteArray) : AES.CFB8.Key, BaseKey(key) {
        override fun cipher(): IvCipher = CCAesIvCipher(
            algorithm = kCCAlgorithmAES,
            mode = kCCModeCFB8,
            padding = ccNoPadding,
            key = key,
            ivSize = 16
        )
    }
}
