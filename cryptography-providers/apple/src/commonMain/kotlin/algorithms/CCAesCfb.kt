/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.algorithms.*
import kotlinx.cinterop.*
import platform.CoreCrypto.*

internal object CCAesCfb : CCAes<AES.CFB.Key>(), AES.CFB {
    override fun wrapKey(key: ByteArray): AES.CFB.Key = AesCfbKey(key)

    private class AesCfbKey(private val key: ByteArray) : AES.CFB.Key {
        override fun cipher(): AES.IvCipher = CCAesIvCipher(
            algorithm = kCCAlgorithmAES,
            mode = kCCModeCFB,
            padding = 0.convert(), // not applicable
            key = key,
            ivSize = 16
        )

        override fun encodeToByteArrayBlocking(format: AES.Key.Format): ByteArray = when (format) {
            AES.Key.Format.RAW -> key.copyOf()
            AES.Key.Format.JWK -> error("JWK is not supported")
        }
    }
}
