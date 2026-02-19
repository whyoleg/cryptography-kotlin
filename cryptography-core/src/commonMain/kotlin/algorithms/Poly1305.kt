/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Poly1305 : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<Poly1305> get() = Companion

    public companion object : CryptographyAlgorithmId<Poly1305>("Poly1305")

    public fun keyDecoder(): Decoder<Key.Format, Key>
    public fun keyGenerator(): KeyGenerator<Key>

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface Key : Encodable<Key.Format> {
        public fun signatureGenerator(): SignatureGenerator
        public fun signatureVerifier(): SignatureVerifier

        public enum class Format : EncodingFormat { RAW }
    }
}
