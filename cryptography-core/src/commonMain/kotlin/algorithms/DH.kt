/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.symmetric.HMAC.Key
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.derivation.*

// TODO: implement DH and only then complete design of derivation
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface DH : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<DH> get() = Companion

    public companion object : CryptographyAlgorithmId<DH>("DH")

    public fun keyDecoder(): KeyDecoder<Key.Format, Key>
    public fun keyGenerator(): KeyGenerator<Key>

    public interface Key : EncodableKey<Key.Format> {
        public fun sharedSecretDerivation(primeModulus: BigInt, generator: BigInt): SharedSecretDerivation<Key>

        public enum class Format : KeyFormat {
            // raw encodes X/Y as BigInt in two's complement
            RAW,
            DER
        }
    }
}
