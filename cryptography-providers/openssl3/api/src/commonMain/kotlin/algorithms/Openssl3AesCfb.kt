/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.operations.*

internal object Openssl3AesCfb : AES.CFB, BaseAes<AES.CFB.Key>() {
    override fun wrapKey(rawKey: ByteArray): AES.CFB.Key = AesCfbKey(rawKey)

    private class AesCfbKey(key: ByteArray) : AES.CFB.Key, BaseKey(key) {
        private val algorithm = when (key.size.bytes) {
            AES.Key.Size.B128 -> "AES-128-CFB"
            AES.Key.Size.B192 -> "AES-192-CFB"
            AES.Key.Size.B256 -> "AES-256-CFB"
            else              -> error("Unsupported key size")
        }

        private val cipher = NativeResource(checkError(EVP_CIPHER_fetch(null, algorithm, null)), ::EVP_CIPHER_free)

        override fun cipher(): IvCipher {
            return Openssl3IvCipher(cipher, key, ivSize = 16)
        }
    }
}
