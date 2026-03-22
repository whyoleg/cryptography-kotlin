/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*

/**
 * Edwards-curve Digital Signature Algorithm (EdDSA)
 * as defined in [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032).
 *
 * EdDSA provides digital signature generation and verification using twisted Edwards curves.
 * Unlike [ECDSA], EdDSA is deterministic (no random nonce) and does not require a separate digest parameter —
 * the hash is built into the algorithm.
 *
 * ```
 * val keys = provider.get(EdDSA).keyPairGenerator(EdDSA.Curve.Ed25519).generateKey()
 * val signature = keys.privateKey.signatureGenerator().generateSignature(data)
 * keys.publicKey.signatureVerifier().verifySignature(data, signature)
 * ```
 *
 * For signatures using Weierstrass curves, see [ECDSA].
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface EdDSA : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<EdDSA> get() = Companion

    public companion object : CryptographyAlgorithmId<EdDSA>("EdDSA")

    /**
     * Supported EdDSA curves.
     */
    public enum class Curve {
        /**
         * Ed25519 curve, based on Curve25519, defined in [RFC 8032 Section 5.1](https://datatracker.ietf.org/doc/html/rfc8032#section-5.1).
         */
        Ed25519,

        /**
         * Ed448 curve, based on Curve448-Goldilocks, defined in [RFC 8032 Section 5.2](https://datatracker.ietf.org/doc/html/rfc8032#section-5.2).
         */
        Ed448,
    }

    /**
     * Returns a [Decoder] that decodes EdDSA public keys on the given [curve]
     * from the specified [PublicKey.Format].
     */
    public fun publicKeyDecoder(curve: Curve): Decoder<PublicKey.Format, PublicKey>

    /**
     * Returns a [Decoder] that decodes EdDSA private keys on the given [curve]
     * from the specified [PrivateKey.Format].
     */
    public fun privateKeyDecoder(curve: Curve): Decoder<PrivateKey.Format, PrivateKey>

    /**
     * Returns a [KeyGenerator] that generates EdDSA key pairs on the given [curve].
     */
    public fun keyPairGenerator(curve: Curve): KeyGenerator<KeyPair>

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface KeyPair {
        public val publicKey: PublicKey
        public val privateKey: PrivateKey
    }

    /**
     * An EdDSA public key that provides signature verification via [signatureVerifier].
     */
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PublicKey : Encodable<PublicKey.Format> {
        /**
         * Returns a [SignatureVerifier] that verifies EdDSA signatures.
         */
        public fun signatureVerifier(): SignatureVerifier

        /**
         * Encoding formats for EdDSA public keys.
         */
        public sealed class Format : EncodingFormat {
            final override fun toString(): String = name

            /**
             * JSON Web Key format
             * as defined in [RFC 8037](https://datatracker.ietf.org/doc/html/rfc8037).
             */
            public data object JWK : Format() {
                override val name: String get() = "JWK"
            }

            /**
             * Raw public key encoding
             * as defined in [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032).
             */
            public data object RAW : Format() {
                override val name: String get() = "RAW"
            }

            /**
             * DER encoding of `SubjectPublicKeyInfo`
             * as defined in [RFC 8410](https://datatracker.ietf.org/doc/html/rfc8410).
             */
            public data object DER : Format() {
                override val name: String get() = "DER"
            }

            /**
             * [PEM](https://datatracker.ietf.org/doc/html/rfc7468) encoding of `SubjectPublicKeyInfo`
             * as defined in [RFC 8410](https://datatracker.ietf.org/doc/html/rfc8410).
             */
            public data object PEM : Format() {
                override val name: String get() = "PEM"
            }
        }
    }

    /**
     * An EdDSA private key that provides signature generation via [signatureGenerator].
     */
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PrivateKey : Encodable<PrivateKey.Format>, PublicKeyAccessor<PublicKey> {
        /**
         * Returns a [SignatureGenerator] that generates EdDSA signatures.
         */
        public fun signatureGenerator(): SignatureGenerator

        /**
         * Encoding formats for EdDSA private keys.
         */
        public sealed class Format : EncodingFormat {
            final override fun toString(): String = name

            /**
             * JSON Web Key format
             * as defined in [RFC 8037](https://datatracker.ietf.org/doc/html/rfc8037).
             */
            public data object JWK : Format() {
                override val name: String get() = "JWK"
            }

            /**
             * Raw seed encoding
             * as defined in [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032).
             */
            public data object RAW : Format() {
                override val name: String get() = "RAW"
            }

            /**
             * DER encoding of `PrivateKeyInfo` (PKCS#8)
             * as defined in [RFC 8410](https://datatracker.ietf.org/doc/html/rfc8410).
             */
            public data object DER : Format() {
                override val name: String get() = "DER"
            }

            /**
             * [PEM](https://datatracker.ietf.org/doc/html/rfc7468) encoding of `PrivateKeyInfo` (PKCS#8)
             * as defined in [RFC 8410](https://datatracker.ietf.org/doc/html/rfc8410).
             */
            public data object PEM : Format() {
                override val name: String get() = "PEM"
            }
        }
    }
}
