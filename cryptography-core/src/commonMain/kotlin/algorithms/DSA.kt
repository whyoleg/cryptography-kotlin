/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface DSA : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<DSA> get() = Companion

    public companion object : CryptographyAlgorithmId<DSA>("DSA")

    public fun publicKeyDecoder(): Decoder<PublicKey.Format, PublicKey>
    public fun privateKeyDecoder(): Decoder<PrivateKey.Format, PrivateKey>

    public fun parametersDecoder(): Decoder<Parameters.Format, Parameters>

    /**
     * Creates a generator for DSA domain parameters.
     *
     * DSA parameters consist of a prime modulus [p] and a subgroup of prime order [q], with generator [g]
     * (commonly referred to as (p, q, g)).
     *
     * - [pBits] controls the size of the prime modulus `p` (typical values: 2048 or 3072 bits).
     * - [qBits] controls the size of the subgroup order `q` (typical values: 224 or 256 bits for `pBits=2048`,
     *   and 256 bits for `pBits=3072`).
     *
     * If [qBits] is `null`, the provider chooses a suitable default for the given [pBits].
     *
     * Note: not all providers/platforms support explicit `qBits` selection. In such cases, implementations may
     * ignore [qBits].
     */
    public fun parametersGenerator(pBits: BinarySize, qBits: BinarySize? = null): ParametersGenerator

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

            // DER encoding of DSAParameters ASN.1 structure: SEQUENCE { p, q, g }
            public data object DER : Format() {
                override val name: String get() = "DER"
            }

            // PEM encoding with "DSA PARAMETERS" label
            public data object PEM : Format() {
                override val name: String get() = "PEM"
            }
        }
    }

    // Convenience: provider may implement this via parametersGenerator(pBits = keySize, qBits = null)
    public fun keyPairGenerator(
        keySize: BinarySize = 2048.bits,
    ): KeyGenerator<KeyPair>

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface KeyPair {
        public val publicKey: PublicKey
        public val privateKey: PrivateKey
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PublicKey : Encodable<PublicKey.Format> {
        public sealed class Format : EncodingFormat {
            final override fun toString(): String = name

            public data object JWK : Format() {
                override val name: String get() = "JWK"
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

        public fun signatureVerifier(
            digest: CryptographyAlgorithmId<Digest>?,
            format: SignatureFormat,
        ): SignatureVerifier
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PrivateKey : Encodable<PrivateKey.Format>, PublicKeyAccessor<PublicKey> {
        public sealed class Format : EncodingFormat {
            final override fun toString(): String = name

            public data object JWK : Format() {
                override val name: String get() = "JWK"
            }

            public data object DER : Format() {
                // via PrivateKeyInfo from PKCS8
                override val name: String get() = "DER"
            }

            public data object PEM : Format() {
                // via PrivateKeyInfo from PKCS8
                override val name: String get() = "PEM"
            }
        }

        public fun signatureGenerator(
            digest: CryptographyAlgorithmId<Digest>?,
            format: SignatureFormat,
        ): SignatureGenerator
    }

    public enum class SignatureFormat {
        // IEEE P1363 / X9.63-like: r || s
        RAW,

        // ASN.1 DER SEQUENCE { r, s }
        DER,
    }
}
