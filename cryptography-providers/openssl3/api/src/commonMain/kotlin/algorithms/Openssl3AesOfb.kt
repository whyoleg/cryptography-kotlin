/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlin.experimental.*
import kotlin.native.ref.*

internal object Openssl3AesOfb : AES.OFB, Openssl3Aes<AES.OFB.Key>() {
    override fun wrapKey(keySize: BinarySize, key: ByteArray): AES.OFB.Key = AesOfbKey(keySize, key)

    private class AesOfbKey(keySize: BinarySize, key: ByteArray) : AES.OFB.Key, AesKey(key) {
        private val algorithm = when (keySize) {
            AES.Key.Size.B128 -> "AES-128-OFB"
            AES.Key.Size.B192 -> "AES-192-OFB"
            AES.Key.Size.B256 -> "AES-256-OFB"
            else              -> error("Unsupported key size")
        }

        private val cipher = EVP_CIPHER_fetch(null, algorithm, null)

        @OptIn(ExperimentalNativeApi::class)
        private val cleaner = createCleaner(cipher, ::EVP_CIPHER_free)

        override fun cipher(): AES.IvCipher {
            return Openssl3AesIvCipher(cipher, key, ivSize = 16)
        }
    }
}
