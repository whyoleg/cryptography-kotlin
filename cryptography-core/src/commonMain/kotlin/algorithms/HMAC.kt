/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface HMAC : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<HMAC> get() = Companion

    public companion object : CryptographyAlgorithmId<HMAC>("HMAC")

    public fun keyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<Key.Format, Key>
    public fun keyGenerator(digest: CryptographyAlgorithmId<Digest> = SHA512): KeyGenerator<Key>

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface Key : EncodableKey<Key.Format> {
        public fun signatureGenerator(): SignatureGenerator
        public fun signatureVerifier(): SignatureVerifier

        public enum class Format : KeyFormat { RAW, JWK }
    }
}
