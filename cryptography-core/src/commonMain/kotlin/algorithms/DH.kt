/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface DH : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<DH> get() = Companion

    public companion object : CryptographyAlgorithmId<DH>("DH")

    public fun publicKeyDecoder(parameters: Parameters): KeyDecoder<PublicKey.Format, PublicKey>
    public fun privateKeyDecoder(parameters: Parameters): KeyDecoder<PrivateKey.Format, PrivateKey>
    public fun keyPairGenerator(parameters: Parameters): KeyGenerator<KeyPair>

    public class Parameters(
        public val p: BigInt,
        public val g: BigInt,
    )

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface KeyPair : Key {
        public val publicKey: PublicKey
        public val privateKey: PrivateKey
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PublicKey : EncodableKey<PublicKey.Format> {
        public fun sharedSecretGenerator(): SharedSecretGenerator<PrivateKey>

        public sealed class Format : KeyFormat {
            final override fun toString(): String = name

            // raw public key value (y = g^x mod p) as unsigned big-endian bytes
            public data object RAW : Format() {
                override val name: String get() = "RAW"
            }

            // SPKI = SubjectPublicKeyInfo
            public data object DER : Format() {
                override val name: String get() = "DER"
            }

            // SPKI = SubjectPublicKeyInfo
            public data object PEM : Format() {
                override val name: String get() = "PEM"
            }
        }
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PrivateKey : EncodableKey<PrivateKey.Format> {
        public fun sharedSecretGenerator(): SharedSecretGenerator<PublicKey>

        public sealed class Format : KeyFormat {
            final override fun toString(): String = name

            // raw private key value (x) as unsigned big-endian bytes
            public data object RAW : Format() {
                override val name: String get() = "RAW"
            }

            // via PrivateKeyInfo from PKCS8
            public data object DER : Format() {
                override val name: String get() = "DER"
            }

            // via PrivateKeyInfo from PKCS8
            public data object PEM : Format() {
                override val name: String get() = "PEM"
            }
        }
    }
}
