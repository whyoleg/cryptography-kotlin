/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import platform.CoreCrypto.*

internal object CCAesCtr : BaseAes<AES.CTR.Key>(), AES.CTR {
    override fun wrapKey(rawKey: ByteArray): AES.CTR.Key = AesCtrKey(rawKey)

    private class AesCtrKey(key: ByteArray) : AES.CTR.Key, BaseKey(key) {
        override fun cipher(): IvCipher = CCAesIvCipher(
            algorithm = kCCAlgorithmAES,
            mode = kCCModeCTR,
            padding = ccNoPadding,
            key = key,
            ivSize = 16
        )
    }
}
