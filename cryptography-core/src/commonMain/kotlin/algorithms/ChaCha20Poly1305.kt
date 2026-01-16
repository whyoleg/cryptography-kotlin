/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface ChaCha20Poly1305 : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<ChaCha20Poly1305> get() = Companion

    public companion object : CryptographyAlgorithmId<ChaCha20Poly1305>("ChaCha20-Poly1305")

    public fun keyDecoder(): KeyDecoder<Key.Format, Key>
    public fun keyGenerator(): KeyGenerator<Key>

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface Key : EncodableKey<Key.Format> {
        public fun cipher(): IvAuthenticatedCipher

        public enum class Format : KeyFormat { RAW, JWK }
    }
}
