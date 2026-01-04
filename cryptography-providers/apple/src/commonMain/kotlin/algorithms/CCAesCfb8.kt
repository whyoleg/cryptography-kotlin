/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.algorithms.*
import platform.CoreCrypto.*

internal object CCAesCfb8 : CCAes<AES.CFB8.Key>(), AES.CFB8 {
    override fun wrapKey(key: ByteArray): AES.CFB8.Key = AesCFBKey(key)

    private class AesCFBKey(private val key: ByteArray) : AES.CFB8.Key {
        override fun cipher(padding: Boolean): AES.IvCipher = CCAesIvCipher(
            algorithm = kCCAlgorithmAES,
            mode = kCCModeCFB8,
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