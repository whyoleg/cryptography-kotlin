/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms.symmetric

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import kotlinx.io.bytestring.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AES<K : AES.Key> : CryptographyAlgorithm {
    public fun keyDecoder(): KeyDecoder<Key.Format, K>
    public fun keyGenerator(keySize: BinarySize = Key.Size.B256): KeyGenerator<K>

    @Suppress("DEPRECATION_ERROR")
    @Deprecated(
        "Replaced by overload with BinarySize",
        ReplaceWith("keyGenerator(keySize.value)"),
        DeprecationLevel.ERROR
    )
    public fun keyGenerator(keySize: SymmetricKeySize = SymmetricKeySize.B256): KeyGenerator<K> = keyGenerator(keySize.value)

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface Key : EncodableKey<Key.Format> {
        public enum class Format : KeyFormat { RAW, JWK }
        public object Size {
            public val B128: BinarySize get() = 128.bits
            public val B192: BinarySize get() = 192.bits
            public val B256: BinarySize get() = 256.bits
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
    public interface CTR : AES<CTR.Key> {
        override val id: CryptographyAlgorithmId<CTR> get() = Companion

        public companion object : CryptographyAlgorithmId<CTR>("AES-CTR")

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface Key : AES.Key {
            public fun cipher(): IvCipher
        }
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface GCM : AES<GCM.Key> {
        override val id: CryptographyAlgorithmId<GCM> get() = Companion

        public companion object : CryptographyAlgorithmId<GCM>("AES-GCM")

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface Key : AES.Key {
            public fun cipher(tagSize: BinarySize = 128.bits): AuthenticatedCipher
        }
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface IvCipher : IvEncryptor, IvDecryptor

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface IvEncryptor : Encryptor {
        @DelicateCryptographyApi
        public suspend fun encrypt(iv: ByteArray, plaintext: ByteArray): ByteArray = encryptBlocking(iv, plaintext)

        @DelicateCryptographyApi
        public fun encryptBlocking(iv: ByteArray, plaintext: ByteArray): ByteArray

        @DelicateCryptographyApi
        public suspend fun encrypt(iv: ByteString, plaintext: ByteString): ByteString =
            encrypt(iv.asByteArray(), plaintext.asByteArray()).asByteString()

        @DelicateCryptographyApi
        public fun encryptBlocking(iv: ByteString, plaintext: ByteString): ByteString =
            encryptBlocking(iv.asByteArray(), plaintext.asByteArray()).asByteString()
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface IvDecryptor : Decryptor {
        @DelicateCryptographyApi
        public suspend fun decrypt(iv: ByteArray, ciphertext: ByteArray): ByteArray = decryptBlocking(iv, ciphertext)

        @DelicateCryptographyApi
        public fun decryptBlocking(iv: ByteArray, ciphertext: ByteArray): ByteArray

        @DelicateCryptographyApi
        public suspend fun decrypt(iv: ByteString, ciphertext: ByteString): ByteString =
            decrypt(iv.asByteArray(), ciphertext.asByteArray()).asByteString()

        @DelicateCryptographyApi
        public fun decryptBlocking(iv: ByteString, ciphertext: ByteString): ByteString =
            decryptBlocking(iv.asByteArray(), ciphertext.asByteArray()).asByteString()
    }
}
