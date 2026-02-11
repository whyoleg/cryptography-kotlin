/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import platform.CoreCrypto.*

internal object CCAesCfb : BaseAes<AES.CFB.Key>(), AES.CFB {
    override fun wrapKey(rawKey: ByteArray): AES.CFB.Key = AesCfbKey(rawKey)

    private class AesCfbKey(key: ByteArray) : AES.CFB.Key, BaseKey(key) {
        override fun cipher(): IvCipher = CCAesIvCipher(
            algorithm = kCCAlgorithmAES,
            mode = kCCModeCFB,
            padding = ccNoPadding,
            key = key,
            ivSize = 16
        )
    }
}
