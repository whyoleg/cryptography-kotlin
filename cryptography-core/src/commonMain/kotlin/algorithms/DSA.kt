/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*

/**
 * Digital Signature Algorithm (DSA)
 * as defined in [FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final).
 *
 * DSA provides digital signature generation and verification using finite-field arithmetic.
 * Domain [Parameters] define the group and must be generated
 * via [parametersGenerator] or decoded via [parametersDecoder] before key pairs can be created.
 *
 * ```
 * val params = provider.get(DSA).parametersGenerator(2048.bits).generateParameters()
 * val keys = params.keyPairGenerator().generateKey()
 * val signature = keys.privateKey.signatureGenerator(SHA256, DSA.SignatureFormat.DER).generateSignature(data)
 * keys.publicKey.signatureVerifier(SHA256, DSA.SignatureFormat.DER).verifySignature(data, signature)
 * ```
 *
 * For the elliptic curve variant, see [ECDSA].
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface DSA : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<DSA> get() = Companion

    public companion object : CryptographyAlgorithmId<DSA>("DSA")

    /**
     * Returns a [Decoder] that decodes DSA public keys from the specified [PublicKey.Format].
     */
    public fun publicKeyDecoder(): Decoder<PublicKey.Format, PublicKey>

    /**
     * Returns a [Decoder] that decodes DSA private keys from the specified [PrivateKey.Format].
     */
    public fun privateKeyDecoder(): Decoder<PrivateKey.Format, PrivateKey>

    /**
     * Returns a [Decoder] that decodes DSA domain parameters from the specified [Parameters.Format].
     */
    public fun parametersDecoder(): Decoder<Parameters.Format, Parameters>

    /**
     * Returns a [ParametersGenerator] that generates DSA domain parameters
     * with the specified [primeSize] and optional [subprimeSize].
     */
    public fun parametersGenerator(primeSize: BinarySize, subprimeSize: BinarySize? = null): ParametersGenerator<Parameters>

    /**
     * DSA domain parameters that provide key pair generation via [keyPairGenerator].
     */
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface Parameters : Encodable<Parameters.Format> {
        /**
         * Returns a [KeyGenerator] that generates DSA key pairs using these domain parameters.
         */
        public fun keyPairGenerator(): KeyGenerator<KeyPair>

        /**
         * Encoding formats for DSA domain parameters.
         */
        public sealed class Format : EncodingFormat {
            final override fun toString(): String = name

            /**
             * DER encoding of `DSAParameters` ASN.1 structure
             * as defined in [RFC 3279](https://datatracker.ietf.org/doc/html/rfc3279).
             */
            public data object DER : Format() {
                override val name: String get() = "DER"
            }

            /**
             * [PEM](https://datatracker.ietf.org/doc/html/rfc7468) encoding of `DSAParameters` ASN.1 structure
             * as defined in [RFC 3279](https://datatracker.ietf.org/doc/html/rfc3279).
             */
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

    /**
     * A DSA public key that provides signature verification via [signatureVerifier].
     */
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PublicKey : Encodable<PublicKey.Format> {
        /**
         * Encoding formats for DSA public keys.
         */
        public sealed class Format : EncodingFormat {
            final override fun toString(): String = name

            /**
             * DER encoding of `SubjectPublicKeyInfo`
             * as defined in [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280).
             */
            public data object DER : Format() {
                override val name: String get() = "DER"
            }

            /**
             * [PEM](https://datatracker.ietf.org/doc/html/rfc7468) encoding of `SubjectPublicKeyInfo`
             * as defined in [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280).
             */
            public data object PEM : Format() {
                override val name: String get() = "PEM"
            }
        }

        /**
         * Returns a [SignatureVerifier] that verifies signatures using the specified [digest] and [format].
         * Pass `null` for [digest] when verifying pre-hashed data.
         */
        public fun signatureVerifier(
            digest: CryptographyAlgorithmId<Digest>?,
            format: SignatureFormat,
        ): SignatureVerifier
    }

    /**
     * A DSA private key that provides signature generation via [signatureGenerator].
     */
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PrivateKey : Encodable<PrivateKey.Format>, PublicKeyAccessor<PublicKey> {
        /**
         * Encoding formats for DSA private keys.
         */
        public sealed class Format : EncodingFormat {
            final override fun toString(): String = name

            /**
             * DER encoding of `PrivateKeyInfo` (PKCS#8)
             * as defined in [RFC 5958](https://datatracker.ietf.org/doc/html/rfc5958).
             */
            public data object DER : Format() {
                override val name: String get() = "DER"
            }

            /**
             * [PEM](https://datatracker.ietf.org/doc/html/rfc7468) encoding of `PrivateKeyInfo` (PKCS#8)
             * as defined in [RFC 5958](https://datatracker.ietf.org/doc/html/rfc5958).
             */
            public data object PEM : Format() {
                override val name: String get() = "PEM"
            }
        }

        /**
         * Returns a [SignatureGenerator] that generates signatures using the specified [digest] and [format].
         * Pass `null` for [digest] when signing pre-hashed data.
         */
        public fun signatureGenerator(
            digest: CryptographyAlgorithmId<Digest>?,
            format: SignatureFormat,
        ): SignatureGenerator
    }

    /**
     * Encoding format for DSA signatures.
     */
    public enum class SignatureFormat {
        /**
         * IEEE P1363 format: fixed-length concatenation of `r || s`.
         *
         * Each value is zero-padded to the subprime size.
         * Defined in IEEE P1363 and also described in
         * [RFC 7518 Section 3.4](https://datatracker.ietf.org/doc/html/rfc7518#section-3.4).
         */
        RAW,

        /**
         * ASN.1 DER-encoded `SEQUENCE { INTEGER r, INTEGER s }`.
         *
         * Variable length.
         * Defined in [RFC 3279 Section 2.2.3](https://datatracker.ietf.org/doc/html/rfc3279#section-2.2.3).
         */
        DER
    }
}
