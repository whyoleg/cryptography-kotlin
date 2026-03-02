/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.operations.*
import kotlinx.cinterop.*
import kotlin.experimental.*
import kotlin.native.ref.*

internal object Openssl3ChaCha20Poly1305 : BaseChaCha20Poly1305() {
    override fun wrapKey(rawKey: ByteArray): ChaCha20Poly1305.Key = ChaCha20Poly1305Key(rawKey)

    private class ChaCha20Poly1305Key(key: ByteArray) : BaseKey(key) {
        private val cipher = EVP_CIPHER_fetch(null, "ChaCha20-Poly1305", null)

        @OptIn(ExperimentalNativeApi::class)
        private val cleaner = createCleaner(cipher, ::EVP_CIPHER_free)

        override fun cipher(): IvAuthenticatedCipher = Openssl3ChaCha20Poly1305Cipher()

        private inner class Openssl3ChaCha20Poly1305Cipher : Openssl3IvAuthenticatedCipher(
            cipher = cipher,
            key = key,
            tagSize = 16,
            implicitIvSize = 12
        ) {
            override fun MemScope.createParams(ivSize: Int): CValuesRef<OSSL_PARAM>? = null
            override fun MemScope.configureContext(context: CPointer<EVP_CIPHER_CTX>?, inputSize: Int) {}
            override fun validateIvSize(ivSize: Int) {
                require(ivSize == implicitIvSize) { "IV size is wrong" }
            }
        }
    }
}
