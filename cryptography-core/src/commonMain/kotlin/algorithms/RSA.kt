/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*

/**
 * RSA asymmetric cryptography algorithm
 * as defined in [RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017).
 *
 * RSA provides public-key encryption and digital signatures based on the difficulty
 * of factoring large integers. Multiple padding schemes are available:
 * * [OAEP] — authenticated encryption (recommended for new applications).
 * * [PSS] — probabilistic signatures (recommended for new applications).
 * * [PKCS1] — legacy encryption and signatures.
 * * [RAW] — unpadded operations (unsafe for general use).
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface RSA<
        PublicK : RSA.PublicKey,
        PrivateK : RSA.PrivateKey<PublicK>,
        KP : RSA.KeyPair<PublicK, PrivateK>,
        > : CryptographyAlgorithm {
    /**
     * Returns a [Decoder] that decodes RSA public keys for the given [digest]
     * from the specified [PublicKey.Format].
     */
    public fun publicKeyDecoder(digest: CryptographyAlgorithmId<Digest>): Decoder<PublicKey.Format, PublicK>

    /**
     * Returns a [Decoder] that decodes RSA private keys for the given [digest]
     * from the specified [PrivateKey.Format].
     */
    public fun privateKeyDecoder(digest: CryptographyAlgorithmId<Digest>): Decoder<PrivateKey.Format, PrivateK>

    /**
     * Returns a [KeyGenerator] that generates RSA key pairs with the given parameters.
     *
     * Common [keySize] values: 2048 bits (minimum acceptable), 3072 bits (recommended), 4096 bits (default, maximum security margin).
     */
    public fun keyPairGenerator(
        keySize: BinarySize = 4096.bits,
        digest: CryptographyAlgorithmId<Digest> = SHA512,
        publicExponent: BigInt = 65537.toBigInt(),
    ): KeyGenerator<KP>

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface KeyPair<PublicK : PublicKey, PrivateK : PrivateKey<PublicK>> {
        public val publicKey: PublicK
        public val privateKey: PrivateK
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PublicKey : Encodable<PublicKey.Format> {
        /**
         * Encoding formats for RSA public keys.
         */
        public sealed class Format : EncodingFormat {
            final override fun toString(): String = name

            /**
             * JSON Web Key format
             * as defined in [RFC 7518 Section 6.3](https://datatracker.ietf.org/doc/html/rfc7518#section-6.3).
             */
            public data object JWK : Format() {
                override val name: String get() = "JWK"
            }

            /**
             * DER encoding of RSA public key.
             */
            public sealed class DER : Format() {
                /**
                 * DER encoding of `SubjectPublicKeyInfo`
                 * as defined in [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280).
                 */
                public companion object Generic : DER() {
                    override val name: String get() = "DER"
                }

                /**
                 * DER encoding of `RSAPublicKey` (PKCS#1)
                 * as defined in [RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017).
                 */
                public data object PKCS1 : DER() {
                    override val name: String get() = "DER/PKCS#1"
                }
            }

            /**
             * [PEM](https://datatracker.ietf.org/doc/html/rfc7468) encoding of RSA public key.
             */
            public sealed class PEM : Format() {
                /**
                 * [PEM](https://datatracker.ietf.org/doc/html/rfc7468) encoding of `SubjectPublicKeyInfo`
                 * as defined in [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280).
                 */
                public companion object Generic : PEM() {
                    override val name: String get() = "PEM"
                }

                /**
                 * [PEM](https://datatracker.ietf.org/doc/html/rfc7468) encoding of `RSAPublicKey` (PKCS#1)
                 * as defined in [RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017).
                 */
                public data object PKCS1 : PEM() {
                    override val name: String get() = "PEM/PKCS#1"
                }
            }
        }
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PrivateKey<PublicK : PublicKey> : Encodable<PrivateKey.Format>, PublicKeyAccessor<PublicK> {
        /**
         * Encoding formats for RSA private keys.
         */
        public sealed class Format : EncodingFormat {
            final override fun toString(): String = name

            /**
             * JSON Web Key format
             * as defined in [RFC 7518 Section 6.3](https://datatracker.ietf.org/doc/html/rfc7518#section-6.3).
             */
            public data object JWK : Format() {
                override val name: String get() = "JWK"
            }

            /**
             * DER encoding of RSA private key.
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
                 * DER encoding of `RSAPrivateKey` (PKCS#1)
                 * as defined in [RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017).
                 */
                public data object PKCS1 : DER() {
                    override val name: String get() = "DER/PKCS#1"
                }
            }

            /**
             * [PEM](https://datatracker.ietf.org/doc/html/rfc7468) encoding of RSA private key.
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
                 * [PEM](https://datatracker.ietf.org/doc/html/rfc7468) encoding of `RSAPrivateKey` (PKCS#1)
                 * as defined in [RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017).
                 */
                public data object PKCS1 : PEM() {
                    override val name: String get() = "PEM/PKCS#1"
                }
            }
        }
    }

    /**
     * RSA with Optimal Asymmetric Encryption Padding (OAEP)
     * as defined in [RFC 8017 Section 7.1](https://datatracker.ietf.org/doc/html/rfc8017#section-7.1).
     *
     * Provides asymmetric encryption with support for associated data (labels).
     *
     * ```
     * val keys = provider.get(RSA.OAEP).keyPairGenerator().generateKey()
     * val ciphertext = keys.publicKey.encryptor().encrypt(plaintext)
     * val decrypted = keys.privateKey.decryptor().decrypt(ciphertext)
     * ```
     */
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface OAEP : RSA<OAEP.PublicKey, OAEP.PrivateKey, OAEP.KeyPair> {
        override val id: CryptographyAlgorithmId<OAEP> get() = Companion

        public companion object : CryptographyAlgorithmId<OAEP>("RSA-OAEP")

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface KeyPair : RSA.KeyPair<PublicKey, PrivateKey>

        /**
         * An RSA-OAEP public key that provides encryption via [encryptor].
         */
        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface PublicKey : RSA.PublicKey {
            /**
             * Returns an [AuthenticatedEncryptor] that encrypts data with OAEP padding.
             */
            public fun encryptor(): AuthenticatedEncryptor
        }

        /**
         * An RSA-OAEP private key that provides decryption via [decryptor].
         */
        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface PrivateKey : RSA.PrivateKey<PublicKey> {
            /**
             * Returns an [AuthenticatedDecryptor] that decrypts data with OAEP padding.
             */
            public fun decryptor(): AuthenticatedDecryptor
        }
    }

    /**
     * RSA Probabilistic Signature Scheme (PSS)
     * as defined in [RFC 8017 Section 8.1](https://datatracker.ietf.org/doc/html/rfc8017#section-8.1).
     *
     * Provides digital signature generation and verification with a probabilistic padding scheme.
     *
     * ```
     * val keys = provider.get(RSA.PSS).keyPairGenerator().generateKey()
     * val signature = keys.privateKey.signatureGenerator().generateSignature(data)
     * keys.publicKey.signatureVerifier().verifySignature(data, signature)
     * ```
     *
     * For the legacy signature padding scheme, see [PKCS1].
     */
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PSS : RSA<PSS.PublicKey, PSS.PrivateKey, PSS.KeyPair> {
        override val id: CryptographyAlgorithmId<PSS> get() = Companion

        public companion object : CryptographyAlgorithmId<PSS>("RSA-PSS")

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface KeyPair : RSA.KeyPair<PublicKey, PrivateKey>

        /**
         * An RSA-PSS public key that provides signature verification via [signatureVerifier].
         */
        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface PublicKey : RSA.PublicKey {
            /**
             * Returns a [SignatureVerifier] using a salt size equal to the digest output size.
             */
            public fun signatureVerifier(): SignatureVerifier

            /**
             * Returns a [SignatureVerifier] using the given [saltSize].
             */
            public fun signatureVerifier(saltSize: BinarySize): SignatureVerifier
        }

        /**
         * An RSA-PSS private key that provides signature generation via [signatureGenerator].
         */
        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface PrivateKey : RSA.PrivateKey<PublicKey> {
            /**
             * Returns a [SignatureGenerator] using a salt size equal to the digest output size.
             */
            public fun signatureGenerator(): SignatureGenerator

            /**
             * Returns a [SignatureGenerator] using the given [saltSize].
             */
            public fun signatureGenerator(saltSize: BinarySize): SignatureGenerator
        }
    }

    /**
     * RSA with PKCS#1 v1.5 padding
     * as defined in [RFC 8017 Sections 7.2 and 8.2](https://datatracker.ietf.org/doc/html/rfc8017#section-7.2).
     *
     * Provides both encryption and digital signatures using the legacy PKCS#1 v1.5 padding scheme.
     *
     * ```
     * val keys = provider.get(RSA.PKCS1).keyPairGenerator().generateKey()
     * val signature = keys.privateKey.signatureGenerator().generateSignature(data)
     * keys.publicKey.signatureVerifier().verifySignature(data, signature)
     * ```
     *
     * Prefer [OAEP] for encryption and [PSS] for signatures in new applications.
     */
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PKCS1 : RSA<PKCS1.PublicKey, PKCS1.PrivateKey, PKCS1.KeyPair> {
        override val id: CryptographyAlgorithmId<PKCS1> get() = Companion

        public companion object : CryptographyAlgorithmId<PKCS1>("RSA-PKCS1-V1.5")

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface KeyPair : RSA.KeyPair<PublicKey, PrivateKey>

        /**
         * An RSA-PKCS1 public key that provides signature verification via [signatureVerifier] and encryption via [encryptor].
         */
        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface PublicKey : RSA.PublicKey {
            /**
             * Returns a [SignatureVerifier] using PKCS#1 v1.5 signature padding.
             */
            public fun signatureVerifier(): SignatureVerifier

            /**
             * Returns an [Encryptor] using PKCS#1 v1.5 encryption padding.
             */
            @DelicateCryptographyApi
            public fun encryptor(): Encryptor
        }

        /**
         * An RSA-PKCS1 private key that provides signature generation via [signatureGenerator] and decryption via [decryptor].
         */
        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface PrivateKey : RSA.PrivateKey<PublicKey> {
            /**
             * Returns a [SignatureGenerator] using PKCS#1 v1.5 signature padding.
             */
            public fun signatureGenerator(): SignatureGenerator

            /**
             * Returns a [Decryptor] using PKCS#1 v1.5 encryption padding.
             */
            @DelicateCryptographyApi
            public fun decryptor(): Decryptor
        }
    }

    /**
     * Raw RSA without padding (textbook RSA).
     *
     * Performs the raw RSA primitive without any padding scheme.
     *
     * ```
     * val keys = provider.get(RSA.RAW).keyPairGenerator().generateKey()
     * val ciphertext = keys.publicKey.encryptor().encrypt(plaintext)
     * val decrypted = keys.privateKey.decryptor().decrypt(ciphertext)
     * ```
     *
     * Unsafe for general use — prefer [OAEP] for encryption and [PSS] for signatures.
     */
    @DelicateCryptographyApi
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface RAW : RSA<RAW.PublicKey, RAW.PrivateKey, RAW.KeyPair> {
        override val id: CryptographyAlgorithmId<RAW> get() = Companion

        public companion object : CryptographyAlgorithmId<RAW>("RSA-RAW")

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface KeyPair : RSA.KeyPair<PublicKey, PrivateKey>

        /**
         * A raw RSA public key that provides encryption via [encryptor].
         */
        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface PublicKey : RSA.PublicKey {
            /**
             * Returns an [Encryptor] that performs raw RSA encryption without padding.
             */
            public fun encryptor(): Encryptor
        }

        /**
         * A raw RSA private key that provides decryption via [decryptor].
         */
        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface PrivateKey : RSA.PrivateKey<PublicKey> {
            /**
             * Returns a [Decryptor] that performs raw RSA decryption without padding.
             */
            public fun decryptor(): Decryptor
        }
    }
}
