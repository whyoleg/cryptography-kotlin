/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface DH : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<*> get() = Companion

    public companion object : CryptographyAlgorithmId<DH>("DH")

    public fun publicKeyDecoder(): KeyDecoder<PublicKey.Format, PublicKey>
    public fun privateKeyDecoder(): KeyDecoder<PrivateKey.Format, PrivateKey>

    public fun parametersDecoder(): MaterialDecoder<Parameters.Format, Parameters>
    public fun parametersGenerator(): MaterialGenerator<Parameters>

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface Parameters : Material {
        public val p: BigInt
        public val g: BigInt
        public val l: BinarySize

        public fun keyPairGenerator(): KeyGenerator<KeyPair>

        public sealed class Format : KeyFormat {
            final override fun toString(): String = name

            public data object DER : Format() {
                override val name: String get() = "DER"
            }

            public data object PEM : Format() {
                override val name: String get() = "PEM"
            }
        }
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface KeyPair : Key {
        public val publicKey: PublicKey
        public val privateKey: PrivateKey
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PublicKey : EncodableKey<PublicKey.Format> {
        public val parameters: Parameters

        public sealed class Format : KeyFormat {
            final override fun toString(): String = name

            // SPKI = SubjectPublicKeyInfo
            public data object DER : Format() {
                override val name: String get() = "DER"
            }

            // SPKI = SubjectPublicKeyInfo
            public data object PEM : Format() {
                override val name: String get() = "PEM"
            }
        }

        public fun sharedSecretGenerator(): SharedSecretGenerator<PrivateKey>
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PrivateKey : EncodableKey<PrivateKey.Format> {
        public val parameters: Parameters

        public sealed class Format : KeyFormat {
            final override fun toString(): String = name

            // via PrivateKeyInfo from PKCS8
            public data object DER : Format() {
                override val name: String get() = "DER"
            }

            // via PrivateKeyInfo from PKCS8
            public data object PEM : Format() {
                override val name: String get() = "PEM"
            }
        }

        public fun sharedSecretGenerator(): SharedSecretGenerator<PublicKey>
    }
}
