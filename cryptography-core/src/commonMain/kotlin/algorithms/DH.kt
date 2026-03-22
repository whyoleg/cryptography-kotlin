/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*

/**
 * Classic finite-field Diffie-Hellman (DH) key agreement
 * as defined in [RFC 2631](https://datatracker.ietf.org/doc/html/rfc2631).
 *
 * DH allows two parties to establish a shared secret over an insecure channel
 * using arithmetic in a finite field defined by domain [Parameters].
 * Parameters must be generated via [parametersGenerator] or decoded via [parametersDecoder]
 * before key pairs can be created.
 * [RFC 3526](https://datatracker.ietf.org/doc/html/rfc3526) defines well-known groups
 * that can be decoded from their standard representations.
 *
 * ```
 * val params = provider.get(DH).parametersGenerator(2048.bits).generateParameters()
 * val aliceKeys = params.keyPairGenerator().generateKey()
 * val bobKeys = params.keyPairGenerator().generateKey()
 * val sharedSecret = aliceKeys.privateKey.sharedSecretGenerator().generateSharedSecret(bobKeys.publicKey)
 * ```
 *
 * The raw shared secret output should not be used directly as a key.
 * Use a key derivation function like [HKDF] to derive actual keys from the shared secret.
 *
 * For key agreement using elliptic curves, see [ECDH]. For Montgomery curves, see [XDH].
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface DH : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<DH> get() = Companion

    public companion object : CryptographyAlgorithmId<DH>("DH")

    /**
     * Returns a [Decoder] that decodes DH public keys from the specified [PublicKey.Format].
     */
    public fun publicKeyDecoder(): Decoder<PublicKey.Format, PublicKey>

    /**
     * Returns a [Decoder] that decodes DH private keys from the specified [PrivateKey.Format].
     */
    public fun privateKeyDecoder(): Decoder<PrivateKey.Format, PrivateKey>

    /**
     * Returns a [Decoder] that decodes DH domain parameters from the specified [Parameters.Format].
     */
    public fun parametersDecoder(): Decoder<Parameters.Format, Parameters>

    /**
     * Returns a [ParametersGenerator] that generates DH domain parameters
     * with the specified [primeSize] and optional [privateValueSize].
     */
    public fun parametersGenerator(primeSize: BinarySize, privateValueSize: BinarySize? = null): ParametersGenerator<Parameters>

    /**
     * DH domain parameters that provide key pair generation via [keyPairGenerator].
     */
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface Parameters : Encodable<Parameters.Format> {
        /**
         * Returns a [KeyGenerator] that generates DH key pairs using these domain parameters.
         */
        public fun keyPairGenerator(): KeyGenerator<KeyPair>

        /**
         * Encoding formats for DH domain parameters.
         */
        public sealed class Format : EncodingFormat {
            final override fun toString(): String = name

            /**
             * DER encoding of `DHParameter` ASN.1 structure
             * as defined in [RFC 3279](https://datatracker.ietf.org/doc/html/rfc3279).
             */
            public data object DER : Format() {
                override val name: String get() = "DER"
            }

            /**
             * [PEM](https://datatracker.ietf.org/doc/html/rfc7468) encoding of `DHParameter` ASN.1 structure
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
     * A DH public key that provides shared secret computation via [sharedSecretGenerator].
     */
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PublicKey : Encodable<PublicKey.Format> {
        /**
         * Returns a [SharedSecretGenerator] that computes a shared secret
         * using this public key and a [PrivateKey].
         */
        public fun sharedSecretGenerator(): SharedSecretGenerator<PrivateKey>

        /**
         * Encoding formats for DH public keys.
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
    }

    /**
     * A DH private key that provides shared secret computation via [sharedSecretGenerator].
     */
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PrivateKey : Encodable<PrivateKey.Format>, PublicKeyAccessor<PublicKey> {
        /**
         * Returns a [SharedSecretGenerator] that computes a shared secret
         * given the other party's [PublicKey].
         */
        public fun sharedSecretGenerator(): SharedSecretGenerator<PublicKey>

        /**
         * Encoding formats for DH private keys.
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
    }
}
