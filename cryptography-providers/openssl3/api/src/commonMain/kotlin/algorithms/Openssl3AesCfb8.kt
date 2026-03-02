/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.operations.*
import kotlin.experimental.*
import kotlin.native.ref.*

internal object Openssl3AesCfb8 : AES.CFB8, BaseAes<AES.CFB8.Key>() {
    override fun wrapKey(rawKey: ByteArray): AES.CFB8.Key = AesCfb8Key(rawKey)

    private class AesCfb8Key(key: ByteArray) : AES.CFB8.Key, BaseKey(key) {
        private val algorithm = when (key.size.bytes) {
            AES.Key.Size.B128 -> "AES-128-CFB8"
            AES.Key.Size.B192 -> "AES-192-CFB8"
            AES.Key.Size.B256 -> "AES-256-CFB8"
            else              -> error("Unsupported key size")
        }

        private val cipher = EVP_CIPHER_fetch(null, algorithm, null)

        @OptIn(ExperimentalNativeApi::class)
        private val cleaner = createCleaner(cipher, ::EVP_CIPHER_free)

        override fun cipher(): IvCipher {
            return Openssl3IvCipher(cipher, key, ivSize = 16)
        }
    }
}
