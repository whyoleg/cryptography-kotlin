/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.base.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.materials.*

@CryptographyProviderApi
public abstract class BaseAes<K : AES.Key> : AES<K> {
    protected abstract fun wrapKey(rawKey: ByteArray): K

    final override fun keyDecoder(): Decoder<AES.Key.Format, K> = BaseKeyDecoder()
    final override fun keyGenerator(keySize: BinarySize): KeyGenerator<K> = BaseKeyGenerator(keySize)

    private inner class BaseKeyDecoder : Decoder<AES.Key.Format, K> {
        override fun decodeFromByteArrayBlocking(format: AES.Key.Format, bytes: ByteArray): K {
            val rawKey = when (format) {
                AES.Key.Format.RAW -> bytes.copyOf()
                AES.Key.Format.JWK -> JsonWebKeys.decodeSymmetricKey(id, bytes)
            }
            requireAesKeySize(rawKey.size.bytes)
            return wrapKey(rawKey)
        }
    }

    private inner class BaseKeyGenerator(private val keySize: BinarySize) : KeyGenerator<K> {
        init {
            requireAesKeySize(keySize)
        }

        override fun generateKeyBlocking(): K {
            val key = CryptographySystem.getDefaultRandom().nextBytes(keySize.inBytes)
            return wrapKey(key)
        }
    }

    protected abstract inner class BaseKey(
        protected val key: ByteArray,
    ) : AES.Key {
        final override fun encodeToByteArrayBlocking(format: AES.Key.Format): ByteArray = when (format) {
            AES.Key.Format.RAW -> key.copyOf()
            AES.Key.Format.JWK -> JsonWebKeys.encodeSymmetricKey(id, key)
        }
    }

    private fun requireAesKeySize(keySize: BinarySize) {
        require(keySize == AES.Key.Size.B128 || keySize == AES.Key.Size.B192 || keySize == AES.Key.Size.B256) {
            "AES key size must be 128, 192 or 256 bits"
        }
    }
}
