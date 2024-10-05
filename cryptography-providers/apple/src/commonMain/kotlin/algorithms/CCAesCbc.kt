/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.algorithms.*
import platform.CoreCrypto.*

internal object CCAesCbc : CCAes<AES.CBC.Key>(), AES.CBC {
    override fun wrapKey(key: ByteArray): AES.CBC.Key = AesCbcKey(key)

    private class AesCbcKey(private val key: ByteArray) : AES.CBC.Key {
        override fun cipher(padding: Boolean): AES.IvCipher = CCAesIvCipher(
            algorithm = kCCAlgorithmAES,
            mode = kCCModeCBC,
            padding = if (padding) ccPKCS7Padding else ccNoPadding,
            key = key,
            ivSize = 16
        ) {
            require(it % kCCBlockSizeAES128.toInt() == 0) { "Ciphertext is not padded" }
        }

        override fun encodeToByteArrayBlocking(format: AES.Key.Format): ByteArray = when (format) {
            AES.Key.Format.RAW -> key.copyOf()
            AES.Key.Format.JWK -> error("JWK is not supported")
        }
    }
}
