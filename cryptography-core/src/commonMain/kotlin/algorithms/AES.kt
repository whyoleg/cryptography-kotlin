/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.materials.*
import dev.whyoleg.cryptography.operations.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AES<K : AES.Key> : CryptographyAlgorithm {
    public fun keyDecoder(): Decoder<Key.Format, K>
    public fun keyGenerator(keySize: BinarySize = Key.Size.B256): KeyGenerator<K>

    @Suppress("DEPRECATION_ERROR")
    @Deprecated(
        "Replaced by overload with BinarySize",
        ReplaceWith("keyGenerator(keySize.value)"),
        DeprecationLevel.ERROR
    )
    public fun keyGenerator(keySize: SymmetricKeySize): KeyGenerator<K> = keyGenerator(keySize.value)

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface Key : Encodable<Key.Format> {
        public enum class Format : EncodingFormat { RAW, JWK }
        public object Size {
            public val B128: BinarySize get() = 128.bits
            public val B192: BinarySize get() = 192.bits
            public val B256: BinarySize get() = 256.bits
        }
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface GCM : AES<GCM.Key> {
        override val id: CryptographyAlgorithmId<GCM> get() = Companion

        public companion object : CryptographyAlgorithmId<GCM>("AES-GCM")

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface Key : AES.Key {
            public fun cipher(tagSize: BinarySize = 128.bits): IvAuthenticatedCipher
        }
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface CTR : AES<CTR.Key> {
        override val id: CryptographyAlgorithmId<CTR> get() = Companion

        public companion object : CryptographyAlgorithmId<CTR>("AES-CTR")

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface Key : AES.Key {
            public fun cipher(): IvCipher
        }
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface CBC : AES<CBC.Key> {
        override val id: CryptographyAlgorithmId<CBC> get() = Companion

        public companion object : CryptographyAlgorithmId<CBC>("AES-CBC")

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface Key : AES.Key {
            public fun cipher(padding: Boolean = true): IvCipher
        }
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface CMAC : AES<CMAC.Key> {
        override val id: CryptographyAlgorithmId<CMAC> get() = Companion

        public companion object : CryptographyAlgorithmId<CMAC>("AES-CMAC")

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface Key : AES.Key {
            public fun signatureGenerator(): SignatureGenerator
            public fun signatureVerifier(): SignatureVerifier
        }
    }

    @DelicateCryptographyApi
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface ECB : AES<ECB.Key> {
        override val id: CryptographyAlgorithmId<ECB> get() = Companion

        public companion object : CryptographyAlgorithmId<ECB>("AES-ECB")

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface Key : AES.Key {
            public fun cipher(padding: Boolean = true): Cipher
        }
    }

    @DelicateCryptographyApi
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface OFB : AES<OFB.Key> {
        override val id: CryptographyAlgorithmId<OFB> get() = Companion

        public companion object : CryptographyAlgorithmId<OFB>("AES-OFB")

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface Key : AES.Key {
            public fun cipher(): IvCipher
        }
    }

    @DelicateCryptographyApi
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface CFB : AES<CFB.Key> {
        override val id: CryptographyAlgorithmId<CFB> get() = Companion

        public companion object : CryptographyAlgorithmId<CFB>("AES-CFB")

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface Key : AES.Key {
            public fun cipher(): IvCipher
        }
    }

    @DelicateCryptographyApi
    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface CFB8 : AES<CFB8.Key> {
        override val id: CryptographyAlgorithmId<CFB8> get() = Companion

        public companion object : CryptographyAlgorithmId<CFB8>("AES-CFB8")

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface Key : AES.Key {
            public fun cipher(): IvCipher
        }
    }
}
