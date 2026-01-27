/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface EdDSA : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<EdDSA> get() = Companion

    public companion object : CryptographyAlgorithmId<EdDSA>("EdDSA")

    public enum class Curve { Ed25519, Ed448 }

    public fun publicKeyDecoder(curve: Curve): KeyDecoder<PublicKey.Format, PublicKey>
    public fun privateKeyDecoder(curve: Curve): KeyDecoder<PrivateKey.Format, PrivateKey>
    public fun keyPairGenerator(curve: Curve): KeyGenerator<KeyPair>

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface KeyPair : Key {
        public val publicKey: PublicKey
        public val privateKey: PrivateKey
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PublicKey : EncodableKey<PublicKey.Format> {
        public fun signatureVerifier(): SignatureVerifier

        public sealed class Format : KeyFormat {
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
    public interface PrivateKey : EncodableKey<PrivateKey.Format>, PublicKeyAccessor<PublicKey> {
        public fun signatureGenerator(): SignatureGenerator

        public sealed class Format : KeyFormat {
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
