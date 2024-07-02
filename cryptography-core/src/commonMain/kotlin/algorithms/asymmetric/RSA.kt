/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms.asymmetric

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.cipher.*
import dev.whyoleg.cryptography.operations.signature.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface RSA<PublicK : RSA.PublicKey, PrivateK : RSA.PrivateKey, KP : RSA.KeyPair<PublicK, PrivateK>> : CryptographyAlgorithm {
    public fun publicKeyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<PublicKey.Format, PublicK>
    public fun privateKeyDecoder(digest: CryptographyAlgorithmId<Digest>): KeyDecoder<PrivateKey.Format, PrivateK>

    public fun keyPairGenerator(
        keySize: BinarySize = 4096.bits,
        digest: CryptographyAlgorithmId<Digest> = SHA512,
        publicExponent: BigInt = 65537.toBigInt(),
    ): KeyGenerator<KP>

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface KeyPair<PublicK : PublicKey, PrivateK : PrivateKey> : Key {
        public val publicKey: PublicK
        public val privateKey: PrivateK
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PublicKey : EncodableKey<PublicKey.Format> {
        public sealed class Format : KeyFormat {
            final override fun toString(): String = name

            public data object JWK : Format() {
                override val name: String get() = "JWK"
            }

            public sealed class DER : Format() {
                public companion object Generic : DER() {
                    override val name: String get() = "DER"
                }

                public data object PKCS1 : DER() {
                    override val name: String get() = "DER/PKCS#1"
                }
            }

            public sealed class PEM : Format() {
                public companion object Generic : PEM() {
                    override val name: String get() = "PEM"
                }

                public data object PKCS1 : PEM() {
                    override val name: String get() = "PEM/PKCS#1"
                }
            }
        }
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PrivateKey : EncodableKey<PrivateKey.Format> {
        public sealed class Format : KeyFormat {
            final override fun toString(): String = name

            public data object JWK : Format() {
                override val name: String get() = "JWK"
            }

            public sealed class DER : Format() {
                public companion object Generic : DER() {
                    override val name: String get() = "DER"
                }

                public data object PKCS1 : DER() {
                    override val name: String get() = "DER/PKCS#1"
                }
            }

            public sealed class PEM : Format() {
                public companion object Generic : PEM() {
                    override val name: String get() = "PEM"
                }

                public data object PKCS1 : PEM() {
                    override val name: String get() = "PEM/PKCS#1"
                }
            }
        }
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface OAEP : RSA<OAEP.PublicKey, OAEP.PrivateKey, OAEP.KeyPair> {
        override val id: CryptographyAlgorithmId<OAEP> get() = Companion

        public companion object : CryptographyAlgorithmId<OAEP>("RSA-OAEP")

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface KeyPair : RSA.KeyPair<PublicKey, PrivateKey>

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface PublicKey : RSA.PublicKey {
            public fun encryptor(): AuthenticatedEncryptor
        }

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface PrivateKey : RSA.PrivateKey {
            public fun decryptor(): AuthenticatedDecryptor
        }
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PSS : RSA<PSS.PublicKey, PSS.PrivateKey, PSS.KeyPair> {
        override val id: CryptographyAlgorithmId<PSS> get() = Companion

        public companion object : CryptographyAlgorithmId<PSS>("RSA-PSS")

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface KeyPair : RSA.KeyPair<PublicKey, PrivateKey>

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface PublicKey : RSA.PublicKey {
            // default salt = digest.outputSize
            public fun signatureVerifier(): SignatureVerifier
            public fun signatureVerifier(saltLength: BinarySize): SignatureVerifier
        }

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface PrivateKey : RSA.PrivateKey {
            // default salt = digest.outputSize
            public fun signatureGenerator(): SignatureGenerator
            public fun signatureGenerator(saltLength: BinarySize): SignatureGenerator
        }
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface PKCS1 : RSA<PKCS1.PublicKey, PKCS1.PrivateKey, PKCS1.KeyPair> {
        override val id: CryptographyAlgorithmId<PKCS1> get() = Companion

        public companion object : CryptographyAlgorithmId<PKCS1>("RSA-PKCS1-V1.5")

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface KeyPair : RSA.KeyPair<PublicKey, PrivateKey>

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface PublicKey : RSA.PublicKey {
            public fun signatureVerifier(): SignatureVerifier

            // digest is not used at all
            @DelicateCryptographyApi
            public fun encryptor(): Encryptor
        }

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface PrivateKey : RSA.PrivateKey {
            public fun signatureGenerator(): SignatureGenerator

            // digest is not used at all
            @DelicateCryptographyApi
            public fun decryptor(): Decryptor
        }
    }

    // digest is not used at all
    @DelicateCryptographyApi
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface RAW : RSA<RAW.PublicKey, RAW.PrivateKey, RAW.KeyPair> {
        override val id: CryptographyAlgorithmId<RAW> get() = Companion

        public companion object : CryptographyAlgorithmId<RAW>("RSA-RAW")

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface KeyPair : RSA.KeyPair<PublicKey, PrivateKey>

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface PublicKey : RSA.PublicKey {
            public fun encryptor(): Encryptor
        }

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface PrivateKey : RSA.PrivateKey {
            public fun decryptor(): Decryptor
        }
    }
}
