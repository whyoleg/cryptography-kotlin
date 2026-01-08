/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.openssl3.internal.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import kotlin.experimental.*
import kotlin.native.ref.*

internal object Openssl3AesCfb8 : AES.CFB8, Openssl3Aes<AES.CFB8.Key>() {
    override fun wrapKey(keySize: BinarySize, key: ByteArray): AES.CFB8.Key = AesCfb8Key(keySize, key)

    private class AesCfb8Key(keySize: BinarySize, key: ByteArray) : AES.CFB8.Key, AesKey(key) {
        private val algorithm = when (keySize) {
            AES.Key.Size.B128 -> "AES-128-CFB8"
            AES.Key.Size.B192 -> "AES-192-CFB8"
            AES.Key.Size.B256 -> "AES-256-CFB8"
            else              -> error("Unsupported key size")
        }

        private val cipher = EVP_CIPHER_fetch(null, algorithm, null)

        @OptIn(ExperimentalNativeApi::class)
        private val cleaner = createCleaner(cipher, ::EVP_CIPHER_free)

        override fun cipher(): AES.IvCipher {
            return Openssl3AesIvCipher(cipher, key, ivSize = 16) { context ->
                checkError(EVP_CIPHER_CTX_set_padding(context, 0))
            }
        }
    }
}
