/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface ChaCha20 : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<ChaCha20> get() = Companion

    public companion object : CryptographyAlgorithmId<ChaCha20>("ChaCha20")

    public fun keyDecoder(): Decoder<Key.Format, Key>
    public fun keyGenerator(): KeyGenerator<Key>

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface Key : Encodable<Key.Format> {
        public fun cipher(): IvCipher

        public enum class Format : EncodingFormat { RAW }
    }
}
