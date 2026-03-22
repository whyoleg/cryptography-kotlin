/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*

/**
 * X25519/X448 Diffie-Hellman key agreement
 * as defined in [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748).
 *
 * XDH allows two parties to establish a shared secret over an insecure channel using modern
 * Montgomery curves. It is the recommended alternative to [ECDH] for new applications,
 * offering simpler implementation and resistance to timing attacks.
 *
 * ```
 * val aliceKeys = provider.get(XDH).keyPairGenerator(XDH.Curve.X25519).generateKey()
 * val bobKeys = provider.get(XDH).keyPairGenerator(XDH.Curve.X25519).generateKey()
 * val sharedSecret = aliceKeys.privateKey.sharedSecretGenerator().generateSharedSecret(bobKeys.publicKey)
 * ```
 *
 * The raw shared secret output should not be used directly as a key.
 * Use a key derivation function like [HKDF] to derive actual keys from the shared secret.
 *
 * For key agreement using Weierstrass curves, see [ECDH].
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface XDH : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<XDH> get() = Companion

    public companion object : CryptographyAlgorithmId<XDH>("XDH")

    /**
     * Supported XDH curves.
     */
    public enum class Curve {
        /**
         * X25519 curve, based on Curve25519, defined in [RFC 7748 Section 5](https://datatracker.ietf.org/doc/html/rfc7748#section-5).
         */
        X25519,

        /**
         * X448 curve, based on Curve448-Goldilocks, defined in [RFC 7748 Section 5](https://datatracker.ietf.org/doc/html/rfc7748#section-5).
         */
        X448,
    }

    /**
     * Returns a [Decoder] that decodes XDH public keys on the given [curve]
     * from the specified [PublicKey.Format].
     */
    public fun publicKeyDecoder(curve: Curve): Decoder<PublicKey.Format, PublicKey>

    /**
     * Returns a [Decoder] that decodes XDH private keys on the given [curve]
     * from the specified [PrivateKey.Format].
     */
    public fun privateKeyDecoder(curve: Curve): Decoder<PrivateKey.Format, PrivateKey>

    /**
     * Returns a [KeyGenerator] that generates XDH key pairs on the given [curve].
     */
    public fun keyPairGenerator(curve: Curve): KeyGenerator<KeyPair>

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface KeyPair {
        public val publicKey: PublicKey
        public val privateKey: PrivateKey
    }

    /**
     * An XDH public key that provides shared secret computation via [sharedSecretGenerator].
     */
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PublicKey : Encodable<PublicKey.Format> {
        /**
         * Returns a [SharedSecretGenerator] that computes a shared secret
         * using this public key and a [PrivateKey].
         */
        public fun sharedSecretGenerator(): SharedSecretGenerator<PrivateKey>

        /**
         * Encoding formats for XDH public keys.
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
             * Raw key encoding
             * as defined in [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748).
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
     * An XDH private key that provides shared secret computation via [sharedSecretGenerator].
     */
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PrivateKey : Encodable<PrivateKey.Format>, PublicKeyAccessor<PublicKey> {
        /**
         * Returns a [SharedSecretGenerator] that computes a shared secret
         * given the other party's [PublicKey].
         */
        public fun sharedSecretGenerator(): SharedSecretGenerator<PublicKey>

        /**
         * Encoding formats for XDH private keys.
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
             * Raw key encoding
             * as defined in [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748).
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
