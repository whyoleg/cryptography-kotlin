/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface DH : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<DH> get() = Companion

    public companion object : CryptographyAlgorithmId<DH>("DH")

    public fun publicKeyDecoder(): Decoder<PublicKey.Format, PublicKey>
    public fun privateKeyDecoder(): Decoder<PrivateKey.Format, PrivateKey>

    public fun parametersDecoder(): Decoder<Parameters.Format, Parameters>
    public fun parametersGenerator(primeSize: BinarySize, privateValueSize: BinarySize? = null): ParametersGenerator

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface ParametersGenerator {
        public suspend fun generateParameters(): Parameters = generateParametersBlocking()
        public fun generateParametersBlocking(): Parameters
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface Parameters : Encodable<Parameters.Format> {
        public fun keyPairGenerator(): KeyGenerator<KeyPair>

        public sealed class Format : EncodingFormat {
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
    public interface KeyPair {
        public val publicKey: PublicKey
        public val privateKey: PrivateKey
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PublicKey : Encodable<PublicKey.Format> {
        public fun sharedSecretGenerator(): SharedSecretGenerator<PrivateKey>

        public sealed class Format : EncodingFormat {
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
    public interface PrivateKey : Encodable<PrivateKey.Format>, PublicKeyAccessor<PublicKey> {
        public fun sharedSecretGenerator(): SharedSecretGenerator<PublicKey>

        public sealed class Format : EncodingFormat {
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
