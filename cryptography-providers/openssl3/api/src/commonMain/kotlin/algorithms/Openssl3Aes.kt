/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.random.*

internal abstract class Openssl3Aes<K : AES.Key> : AES<K> {

    protected abstract fun wrapKey(keySize: BinarySize, key: ByteArray): K

    private val keyDecoder = AesKeyDecoder()
    final override fun keyDecoder(): KeyDecoder<AES.Key.Format, K> = keyDecoder
    final override fun keyGenerator(keySize: BinarySize): KeyGenerator<K> = AesKeyGenerator(keySize)

    private fun requireAesKeySize(keySize: BinarySize) {
        require(keySize == AES.Key.Size.B128 || keySize == AES.Key.Size.B192 || keySize == AES.Key.Size.B256) {
            "AES key size must be 128, 192 or 256 bits"
        }
    }

    private inner class AesKeyDecoder : KeyDecoder<AES.Key.Format, K> {
        override fun decodeFromByteArrayBlocking(format: AES.Key.Format, bytes: ByteArray): K = when (format) {
            AES.Key.Format.RAW -> {
                val keySize = bytes.size.bytes
                requireAesKeySize(keySize)
                wrapKey(keySize, bytes.copyOf())
            }
            AES.Key.Format.JWK -> error("JWK is not supported")
        }
    }

    private inner class AesKeyGenerator(
        private val keySize: BinarySize,
    ) : KeyGenerator<K> {

        init {
            requireAesKeySize(keySize)
        }

        override fun generateKeyBlocking(): K {
            val key = CryptographyRandom.nextBytes(keySize.inBytes)
            return wrapKey(keySize, key)
        }
    }

    protected abstract class AesKey(
        protected val key: ByteArray,
    ) : AES.Key {
        final override fun encodeToByteArrayBlocking(format: AES.Key.Format): ByteArray = when (format) {
            AES.Key.Format.RAW -> key.copyOf()
            AES.Key.Format.JWK -> error("JWK is not supported")
        }
    }
}
