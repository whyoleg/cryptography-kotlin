/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.base.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.materials.*

private const val keySizeBytes: Int = 32

@CryptographyProviderApi
public abstract class BaseChaCha20Poly1305 : ChaCha20Poly1305 {
    protected abstract fun wrapKey(rawKey: ByteArray): ChaCha20Poly1305.Key

    final override fun keyDecoder(): Decoder<ChaCha20Poly1305.Key.Format, ChaCha20Poly1305.Key> = BaseKeyDecoder()
    final override fun keyGenerator(): KeyGenerator<ChaCha20Poly1305.Key> = BaseKeyGenerator()

    private inner class BaseKeyDecoder : Decoder<ChaCha20Poly1305.Key.Format, ChaCha20Poly1305.Key> {
        override fun decodeFromByteArrayBlocking(format: ChaCha20Poly1305.Key.Format, bytes: ByteArray): ChaCha20Poly1305.Key {
            val rawKey = when (format) {
                ChaCha20Poly1305.Key.Format.RAW -> bytes.copyOf()
                ChaCha20Poly1305.Key.Format.JWK -> JsonWebKeys.decodeSymmetricKey(ChaCha20Poly1305, bytes)
            }
            require(rawKey.size == keySizeBytes) { "ChaCha20-Poly1305 key size must be 256 bits" }
            return wrapKey(rawKey)
        }
    }

    private inner class BaseKeyGenerator : KeyGenerator<ChaCha20Poly1305.Key> {
        override fun generateKeyBlocking(): ChaCha20Poly1305.Key {
            val key = CryptographySystem.getDefaultRandom().nextBytes(keySizeBytes)
            return wrapKey(key)
        }
    }

    protected abstract inner class BaseKey(
        protected val key: ByteArray,
    ) : ChaCha20Poly1305.Key {
        final override fun encodeToByteArrayBlocking(format: ChaCha20Poly1305.Key.Format): ByteArray = when (format) {
            ChaCha20Poly1305.Key.Format.RAW -> key.copyOf()
            ChaCha20Poly1305.Key.Format.JWK -> JsonWebKeys.encodeSymmetricKey(ChaCha20Poly1305, key)
        }
    }
}
