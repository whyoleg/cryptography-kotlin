/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*

/**
 * Poly1305 one-time authenticator (RFC 7539).
 *
 * WARNING: Each key must only be used once. Using the same key for multiple
 * messages compromises security.
 */
@DelicateCryptographyApi
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Poly1305 : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<Poly1305> get() = Companion

    public companion object : CryptographyAlgorithmId<Poly1305>("Poly1305") {
        public const val KEY_SIZE: Int = 32
        public const val TAG_SIZE: Int = 16
    }

    public fun keyDecoder(): KeyDecoder<Key.Format, Key>

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface Key : EncodableKey<Key.Format> {
        /**
         * Creates a signature generator for computing Poly1305 tags.
         */
        public fun signatureGenerator(): SignatureGenerator

        /**
         * Creates a signature verifier for verifying Poly1305 tags.
         */
        public fun signatureVerifier(): SignatureVerifier

        public enum class Format : KeyFormat { RAW }
    }
}