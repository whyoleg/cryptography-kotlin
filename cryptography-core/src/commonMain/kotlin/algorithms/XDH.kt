/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface XDH : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<XDH> get() = Companion

    public companion object : CryptographyAlgorithmId<XDH>("XDH")

    public enum class Curve { X25519, X448 }

    public fun publicKeyDecoder(curve: Curve): Decoder<PublicKey.Format, PublicKey>
    public fun privateKeyDecoder(curve: Curve): Decoder<PrivateKey.Format, PrivateKey>
    public fun keyPairGenerator(curve: Curve): KeyGenerator<KeyPair>

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface KeyPair {
        public val publicKey: PublicKey
        public val privateKey: PrivateKey
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PublicKey : Encodable<PublicKey.Format> {
        public fun sharedSecretGenerator(): SharedSecretGenerator<PrivateKey>

        public sealed class Format : EncodingFormat {
            final override fun toString(): String = name

            public data object JWK : Format() {
                override val name: String get() = "JWK"
            }

            public data object RAW : Format() {
                override val name: String get() = "RAW"
            }

            public data object DER : Format() {
                override val name: String get() = "DER"
            }

            public data object PEM : Format() {
                override val name: String get() = "PEM"
            }
        }
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PrivateKey : Encodable<PrivateKey.Format>, PublicKeyAccessor<PublicKey> {
        public fun sharedSecretGenerator(): SharedSecretGenerator<PublicKey>

        public sealed class Format : EncodingFormat {
            final override fun toString(): String = name

            public data object JWK : Format() {
                override val name: String get() = "JWK"
            }

            public data object RAW : Format() {
                override val name: String get() = "RAW"
            }

            public data object DER : Format() {
                override val name: String get() = "DER"
            }

            public data object PEM : Format() {
                override val name: String get() = "PEM"
            }
        }
    }
}
