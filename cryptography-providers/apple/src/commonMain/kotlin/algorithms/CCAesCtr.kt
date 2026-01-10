/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.algorithms.*
import platform.CoreCrypto.*

internal object CCAesCtr : CCAes<AES.CTR.Key>(), AES.CTR {
    override fun wrapKey(key: ByteArray): AES.CTR.Key = AesCtrKey(key)

    private class AesCtrKey(private val key: ByteArray) : AES.CTR.Key {
        override fun cipher(): AES.IvCipher = CCAesIvCipher(
            algorithm = kCCAlgorithmAES,
            mode = kCCModeCTR,
            padding = ccNoPadding,
            key = key,
            ivSize = 16
        )

        override fun encodeToByteArrayBlocking(format: AES.Key.Format): ByteArray = when (format) {
            AES.Key.Format.RAW -> key.copyOf()
            AES.Key.Format.JWK -> error("JWK is not supported")
        }
    }
}
