/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.random.*

internal abstract class CCAes<K : AES.Key> : AES<K> {
    protected abstract fun wrapKey(key: ByteArray): K

    final override fun keyDecoder(): KeyDecoder<AES.Key.Format, K> = AesKeyDecoder()

    final override fun keyGenerator(keySize: SymmetricKeySize): KeyGenerator<K> =
        AesCtrKeyGenerator(keySize.value.inBytes)

    private inner class AesKeyDecoder : KeyDecoder<AES.Key.Format, K> {
        override fun decodeFromBlocking(format: AES.Key.Format, input: ByteArray): K = when (format) {
            AES.Key.Format.RAW -> {
                require(input.size == 16 || input.size == 24 || input.size == 32) {
                    "AES key size must be 128, 192 or 256 bits"
                }
                wrapKey(input.copyOf())
            }
            AES.Key.Format.JWK -> error("JWK is not supported")
        }
    }

    private inner class AesCtrKeyGenerator(private val keySizeBytes: Int) : KeyGenerator<K> {
        override fun generateKeyBlocking(): K {
            val key = CryptographyRandom.nextBytes(keySizeBytes)
            return wrapKey(key)
        }
    }
}
