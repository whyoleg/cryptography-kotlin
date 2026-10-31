/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
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

internal object Openssl3AesCtr : AES.CTR, BaseAes<AES.CTR.Key>() {
    override fun wrapKey(rawKey: ByteArray): AES.CTR.Key = AesCtrKey(rawKey)

    private class AesCtrKey(key: ByteArray) : AES.CTR.Key, BaseKey(key) {
        private val algorithm = when (key.size.bytes) {
            AES.Key.Size.B128 -> "AES-128-CTR"
            AES.Key.Size.B192 -> "AES-192-CTR"
            AES.Key.Size.B256 -> "AES-256-CTR"
            else              -> error("Unsupported key size")
        }

        private val cipher = NativeResource(checkError(EVP_CIPHER_fetch(null, algorithm, null)), ::EVP_CIPHER_free)

        override fun cipher(): IvCipher {
            return Openssl3IvCipher(cipher, key, ivSize = 16)
        }
    }
}
