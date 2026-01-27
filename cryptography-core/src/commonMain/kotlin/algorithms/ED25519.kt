/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface ED25519 : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<ED25519> get() = Companion

    public companion object : CryptographyAlgorithmId<ED25519>("ED25519")

    public fun publicKeyDecoder(): KeyDecoder<PublicKey.Format, PublicKey>
    public fun privateKeyDecoder(): KeyDecoder<PrivateKey.Format, PrivateKey>
    public fun keyPairGenerator(): KeyGenerator<KeyPair>

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

            // 32 bytes raw public key
            public data object RAW : Format() {
                override val name: String get() = "RAW"
            }

            // SubjectPublicKeyInfo (44 bytes)
            public data object DER : Format() {
                override val name: String get() = "DER"
            }

            // PEM encoded SubjectPublicKeyInfo
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

            // 32 bytes seed
            public data object RAW : Format() {
                override val name: String get() = "RAW"
            }

            // PKCS#8 PrivateKeyInfo (48 bytes without public key, ~83 bytes with)
            public data object DER : Format() {
                override val name: String get() = "DER"
            }

            // PEM encoded PrivateKeyInfo
            public data object PEM : Format() {
                override val name: String get() = "PEM"
            }
        }
    }
}
