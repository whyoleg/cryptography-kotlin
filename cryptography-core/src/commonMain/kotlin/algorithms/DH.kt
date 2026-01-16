/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.materials.parameters.*
import dev.whyoleg.cryptography.operations.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface DH : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<DH> get() = Companion

    public companion object : CryptographyAlgorithmId<DH>("DH")

    // Key decoders - parameters are extracted from the DER/PEM encoding
    public fun publicKeyDecoder(): KeyDecoder<PublicKey.Format, PublicKey>
    public fun privateKeyDecoder(): KeyDecoder<PrivateKey.Format, PrivateKey>

    public fun parametersDecoder(): ParameterDecoder<Parameters.Format, Parameters>
    public fun parametersGenerator(primeSize: BinarySize): ParameterGenerator<Parameters>

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface Parameters : EncodableParameters<Parameters.Format> {
        public val p: BigInt
        public val g: BigInt

        public fun keyPairGenerator(): KeyGenerator<KeyPair>

        public sealed class Format : ParameterFormat {
            final override fun toString(): String = name

            // DER encoding of DHParameter ASN.1 structure (RFC 3279)
            public data object DER : Format() {
                override val name: String get() = "DER"
            }

            // PEM encoding with "DH PARAMETERS" label
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
        public val y: BigInt  // public key value (y = g^x mod p)
        public fun sharedSecretGenerator(): SharedSecretGenerator<PrivateKey>

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
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PrivateKey : EncodableKey<PrivateKey.Format> {
        public val parameters: Parameters
        public val x: BigInt  // private key value
        public fun sharedSecretGenerator(): SharedSecretGenerator<PublicKey>

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
    }
}
