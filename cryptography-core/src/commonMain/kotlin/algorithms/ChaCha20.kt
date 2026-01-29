/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*

/**
 * ChaCha20 stream cipher (RFC 7539).
 *
 * This is the raw ChaCha20 cipher without Poly1305 authentication.
 * Use [ChaCha20Poly1305] for authenticated encryption.
 */
@DelicateCryptographyApi
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface ChaCha20 : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<ChaCha20> get() = Companion

    public companion object : CryptographyAlgorithmId<ChaCha20>("ChaCha20")

    public fun keyDecoder(): KeyDecoder<Key.Format, Key>
    public fun keyGenerator(): KeyGenerator<Key>

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface Key : EncodableKey<Key.Format> {
        /**
         * Creates a cipher for encryption/decryption.
         *
         * ChaCha20 uses a 12-byte nonce (IV).
         */
        public fun cipher(): IvCipher

        public enum class Format : KeyFormat { RAW }
    }
}