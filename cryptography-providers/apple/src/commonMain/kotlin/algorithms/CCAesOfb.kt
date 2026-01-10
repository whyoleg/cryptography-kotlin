/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.algorithms.*
import platform.CoreCrypto.*

internal object CCAesOfb : CCAes<AES.OFB.Key>(), AES.OFB {
    override fun wrapKey(key: ByteArray): AES.OFB.Key = AesOfbKey(key)

    private class AesOfbKey(private val key: ByteArray) : AES.OFB.Key {
        override fun cipher(): AES.IvCipher = CCAesIvCipher(
            algorithm = kCCAlgorithmAES,
            mode = kCCModeOFB,
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
