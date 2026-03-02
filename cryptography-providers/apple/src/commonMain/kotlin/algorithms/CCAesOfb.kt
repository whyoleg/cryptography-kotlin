/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import platform.CoreCrypto.*

internal object CCAesOfb : BaseAes<AES.OFB.Key>(), AES.OFB {
    override fun wrapKey(rawKey: ByteArray): AES.OFB.Key = AesOfbKey(rawKey)

    private class AesOfbKey(key: ByteArray) : AES.OFB.Key, BaseKey(key) {
        override fun cipher(): IvCipher = CCAesIvCipher(
            algorithm = kCCAlgorithmAES,
            mode = kCCModeOFB,
            padding = ccNoPadding,
            key = key,
            ivSize = 16
        )
    }
}
