/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*
import kotlin.jvm.*

/**
 * Base interface for elliptic curve algorithms.
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface EC<
        PublicK : EC.PublicKey,
        PrivateK : EC.PrivateKey<PublicK>,
        KP : EC.KeyPair<PublicK, PrivateK>,
        > : CryptographyAlgorithm {

    /**
     * Returns a [Decoder] that decodes EC public keys on the given [curve]
     * from the specified [PublicKey.Format].
     */
    public fun publicKeyDecoder(curve: Curve): Decoder<PublicKey.Format, PublicK>

    /**
     * Returns a [Decoder] that decodes EC private keys on the given [curve]
     * from the specified [PrivateKey.Format].
     */
    public fun privateKeyDecoder(curve: Curve): Decoder<PrivateKey.Format, PrivateK>

    /**
     * Returns a [KeyGenerator] that generates EC key pairs on the given [curve].
     */
    public fun keyPairGenerator(curve: Curve): KeyGenerator<KP>

    /**
     * Identifies an elliptic curve by its standard name.
     *
     * Predefined NIST, secp256k1, and Brainpool curves are available as companion properties.
     * A custom curve can be created by passing its name directly, but not all providers support all curves.
     */
    @JvmInline
    public value class Curve(public val name: String) {
        public companion object {
            /**
             * NIST P-256 curve (also known as secp256r1 or prime256v1), defined in [FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final).
             */
            public val P256: Curve get() = Curve("P-256")

            /**
             * NIST P-384 curve (also known as secp384r1), defined in [FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final).
             */
            public val P384: Curve get() = Curve("P-384")

            /**
             * NIST P-521 curve (also known as secp521r1), defined in [FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final).
             */
            public val P521: Curve get() = Curve("P-521")

            /**
             * secp256k1 curve, widely used in Bitcoin and other cryptocurrencies, defined in [SEC 2](https://www.secg.org/sec2-v2.pdf).
             */
            public val secp256k1: Curve get() = Curve("secp256k1")

            /**
             * Brainpool P-256r1 curve, defined in [RFC 5639](https://datatracker.ietf.org/doc/html/rfc5639).
             */
            public val brainpoolP256r1: Curve get() = Curve("brainpoolP256r1")

            /**
             * Brainpool P-384r1 curve, defined in [RFC 5639](https://datatracker.ietf.org/doc/html/rfc5639).
             */
            public val brainpoolP384r1: Curve get() = Curve("brainpoolP384r1")

            /**
             * Brainpool P-512r1 curve, defined in [RFC 5639](https://datatracker.ietf.org/doc/html/rfc5639).
             */
            public val brainpoolP512r1: Curve get() = Curve("brainpoolP512r1")
        }
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface KeyPair<PublicK : PublicKey, PrivateK : PrivateKey<PublicK>> {
        public val publicKey: PublicK
        public val privateKey: PrivateK
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PublicKey : Encodable<PublicKey.Format> {
        /**
         * Encoding formats for EC public keys.
         */
        public sealed class Format : EncodingFormat {
            final override fun toString(): String = name

            /**
             * JSON Web Key format
             * as defined in [RFC 7518 Section 6.2](https://datatracker.ietf.org/doc/html/rfc7518#section-6.2).
             */
            public data object JWK : Format() {
                override val name: String get() = "JWK"
            }

            /**
             * Raw EC point encoding
             * as defined in [SEC 1, Section 2.3.3](https://www.secg.org/sec1-v2.pdf).
             */
            public sealed class RAW : Format() {

                /**
                 * Uncompressed point encoding: `0x04 || X || Y`
                 * as defined in [SEC 1, Section 2.3.3](https://www.secg.org/sec1-v2.pdf).
                 */
                public companion object Uncompressed : RAW() {
                    override val name: String get() = "RAW"
                }

                /**
                 * Compressed point encoding: `0x02 || X` (even Y) or `0x03 || X` (odd Y)
                 * as defined in [SEC 1, Section 2.3.3](https://www.secg.org/sec1-v2.pdf).
                 */
                public data object Compressed : RAW() {
                    override val name: String get() = "RAW/COMPRESSED"
                }
            }

            /**
             * DER encoding of `SubjectPublicKeyInfo`
             * as defined in [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280)
             * with EC parameters from [RFC 5480](https://datatracker.ietf.org/doc/html/rfc5480).
             */
            public data object DER : Format() {
                override val name: String get() = "DER"
            }

            /**
             * [PEM](https://datatracker.ietf.org/doc/html/rfc7468) encoding of `SubjectPublicKeyInfo`
             * as defined in [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280)
             * with EC parameters from [RFC 5480](https://datatracker.ietf.org/doc/html/rfc5480).
             */
            public data object PEM : Format() {
                override val name: String get() = "PEM"
            }
        }
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PrivateKey<PublicK : PublicKey> : Encodable<PrivateKey.Format>, PublicKeyAccessor<PublicK> {
        /**
         * Encoding formats for EC private keys.
         */
        public sealed class Format : EncodingFormat {
            final override fun toString(): String = name

            /**
             * JSON Web Key format
             * as defined in [RFC 7518 Section 6.2](https://datatracker.ietf.org/doc/html/rfc7518#section-6.2).
             */
            public data object JWK : Format() {
                override val name: String get() = "JWK"
            }

            /**
             * Raw encoding containing only the private key's secret scalar value
             * as a fixed-size big-endian integer
             * as defined in [SEC 1, Section 2.3.7](https://www.secg.org/sec1-v2.pdf).
             */
            public data object RAW : Format() {
                override val name: String get() = "RAW"
            }

            /**
             * DER encoding of EC private key.
             */
            public sealed class DER : Format() {
                /**
                 * DER encoding of `PrivateKeyInfo` (PKCS#8)
                 * as defined in [RFC 5958](https://datatracker.ietf.org/doc/html/rfc5958).
                 */
                public companion object Generic : DER() {
                    override val name: String get() = "DER"
                }

                /**
                 * DER encoding of `ECPrivateKey`
                 * as defined in [RFC 5915](https://datatracker.ietf.org/doc/html/rfc5915).
                 */
                public data object SEC1 : DER() {
                    override val name: String get() = "DER/SEC1"
                }
            }

            /**
             * [PEM](https://datatracker.ietf.org/doc/html/rfc7468) encoding of EC private key.
             */
            public sealed class PEM : Format() {
                /**
                 * [PEM](https://datatracker.ietf.org/doc/html/rfc7468) encoding of `PrivateKeyInfo` (PKCS#8)
                 * as defined in [RFC 5958](https://datatracker.ietf.org/doc/html/rfc5958).
                 */
                public companion object Generic : PEM() {
                    override val name: String get() = "PEM"
                }

                /**
                 * [PEM](https://datatracker.ietf.org/doc/html/rfc7468) encoding of `ECPrivateKey`
                 * as defined in [RFC 5915](https://datatracker.ietf.org/doc/html/rfc5915).
                 */
                public data object SEC1 : PEM() {
                    override val name: String get() = "PEM/SEC1"
                }
            }
        }
    }
}
