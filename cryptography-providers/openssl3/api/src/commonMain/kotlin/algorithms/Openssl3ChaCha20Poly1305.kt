/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.openssl3.internal.cinterop.*
import dev.whyoleg.cryptography.providers.openssl3.operations.*
import kotlinx.cinterop.*
import kotlin.experimental.*
import kotlin.native.ref.*

private const val keySize: Int = 32

internal object Openssl3ChaCha20Poly1305 : ChaCha20Poly1305 {
    override fun keyDecoder(): Decoder<ChaCha20Poly1305.Key.Format, ChaCha20Poly1305.Key> = ChaCha20Poly1305KeyDecoder()
    override fun keyGenerator(): KeyGenerator<ChaCha20Poly1305.Key> = ChaCha20Poly1305KeyGenerator()

    private class ChaCha20Poly1305KeyDecoder : Decoder<ChaCha20Poly1305.Key.Format, ChaCha20Poly1305.Key> {
        override fun decodeFromByteArrayBlocking(format: ChaCha20Poly1305.Key.Format, bytes: ByteArray): ChaCha20Poly1305.Key =
            when (format) {
                ChaCha20Poly1305.Key.Format.RAW -> {
                    require(bytes.size == keySize) { "ChaCha20-Poly1305 key size must be 256 bits" }
                    ChaCha20Poly1305Key(bytes.copyOf())
                }
                ChaCha20Poly1305.Key.Format.JWK -> error("JWK is not supported")
            }
    }

    private class ChaCha20Poly1305KeyGenerator : KeyGenerator<ChaCha20Poly1305.Key> {
        override fun generateKeyBlocking(): ChaCha20Poly1305.Key {
            val key = CryptographySystem.getDefaultRandom().nextBytes(keySize)
            return ChaCha20Poly1305Key(key)
        }
    }

    private class ChaCha20Poly1305Key(private val key: ByteArray) : ChaCha20Poly1305.Key {
        private val cipher = EVP_CIPHER_fetch(null, "ChaCha20-Poly1305", null)

        @OptIn(ExperimentalNativeApi::class)
        private val cleaner = createCleaner(cipher, ::EVP_CIPHER_free)

        override fun cipher(): IvAuthenticatedCipher = Openssl3ChaCha20Poly1305Cipher()

        override fun encodeToByteArrayBlocking(format: ChaCha20Poly1305.Key.Format): ByteArray = when (format) {
            ChaCha20Poly1305.Key.Format.RAW -> key.copyOf()
            ChaCha20Poly1305.Key.Format.JWK -> error("JWK is not supported")
        }

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
