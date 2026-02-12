/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.operations.*
import kotlin.experimental.*
import kotlin.native.ref.*

internal object Openssl3AesCtr : AES.CTR, Openssl3Aes<AES.CTR.Key>() {
    override fun wrapKey(keySize: BinarySize, key: ByteArray): AES.CTR.Key = AesCtrKey(keySize, key)

    private class AesCtrKey(keySize: BinarySize, key: ByteArray) : AES.CTR.Key, AesKey(key) {
        private val algorithm = when (keySize) {
            AES.Key.Size.B128 -> "AES-128-CTR"
            AES.Key.Size.B192 -> "AES-192-CTR"
            AES.Key.Size.B256 -> "AES-256-CTR"
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
