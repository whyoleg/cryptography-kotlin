/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*

internal abstract class CCAes<K : AES.Key> : AES<K> {
    protected abstract fun wrapKey(key: ByteArray): K

    final override fun keyDecoder(): Decoder<AES.Key.Format, K> = AesKeyDecoder()

    final override fun keyGenerator(keySize: BinarySize): KeyGenerator<K> =
        AesCtrKeyGenerator(keySize.inBytes)

    private inner class AesKeyDecoder : Decoder<AES.Key.Format, K> {
        override fun decodeFromByteArrayBlocking(format: AES.Key.Format, bytes: ByteArray): K = when (format) {
            AES.Key.Format.RAW -> {
                require(bytes.size == 16 || bytes.size == 24 || bytes.size == 32) {
                    "AES key size must be 128, 192 or 256 bits"
                }
                wrapKey(bytes.copyOf())
            }
            AES.Key.Format.JWK -> error("JWK is not supported")
        }
    }

    private inner class AesCtrKeyGenerator(private val keySizeBytes: Int) : KeyGenerator<K> {
        override fun generateKeyBlocking(): K {
            val key = CryptographySystem.getDefaultRandom().nextBytes(keySizeBytes)
            return wrapKey(key)
        }
    }
}
