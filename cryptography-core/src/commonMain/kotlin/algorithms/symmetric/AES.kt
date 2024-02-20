/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms.symmetric

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.cipher.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AES<K : AES.Key> : CryptographyAlgorithm {
    public fun keyDecoder(): KeyDecoder<Key.Format, K>
    public fun keyGenerator(keySize: SymmetricKeySize = SymmetricKeySize.B256): KeyGenerator<K>

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface Key : EncodableKey<Key.Format> {
        public enum class Format : KeyFormat { RAW, JWK }
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface CBC : AES<CBC.Key> {
        override val id: CryptographyAlgorithmId<CBC> get() = Companion

        public companion object : CryptographyAlgorithmId<CBC>("AES-CBC")

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface Key : AES.Key {
            public fun cipher(padding: Boolean = true): Cipher
        }

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface Cipher : dev.whyoleg.cryptography.operations.cipher.Cipher, Encryptor, Decryptor

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface Encryptor : dev.whyoleg.cryptography.operations.cipher.Encryptor {
            @DelicateCryptographyApi
            public suspend fun encrypt(iv: ByteArray, plaintextInput: ByteArray): ByteArray = encryptBlocking(iv, plaintextInput)

            @DelicateCryptographyApi
            public fun encryptBlocking(iv: ByteArray, plaintextInput: ByteArray): ByteArray
        }

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface Decryptor : dev.whyoleg.cryptography.operations.cipher.Decryptor {
            @DelicateCryptographyApi
            public suspend fun decrypt(iv: ByteArray, ciphertextInput: ByteArray): ByteArray = decryptBlocking(iv, ciphertextInput)

            @DelicateCryptographyApi
            public fun decryptBlocking(iv: ByteArray, ciphertextInput: ByteArray): ByteArray
        }
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface CTR : AES<CTR.Key> {
        override val id: CryptographyAlgorithmId<CTR> get() = Companion

        public companion object : CryptographyAlgorithmId<CTR>("AES-CTR")

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface Key : AES.Key {
            public fun cipher(): Cipher
        }

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface Cipher : dev.whyoleg.cryptography.operations.cipher.Cipher, Encryptor, Decryptor

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface Encryptor : dev.whyoleg.cryptography.operations.cipher.Encryptor {
            @DelicateCryptographyApi
            public suspend fun encrypt(iv: ByteArray, plaintextInput: ByteArray): ByteArray {
                return encryptBlocking(iv, plaintextInput)
            }

            @DelicateCryptographyApi
            public fun encryptBlocking(iv: ByteArray, plaintextInput: ByteArray): ByteArray
        }

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface Decryptor : dev.whyoleg.cryptography.operations.cipher.Decryptor {
            @DelicateCryptographyApi
            public suspend fun decrypt(iv: ByteArray, ciphertextInput: ByteArray): ByteArray {
                return decryptBlocking(iv, ciphertextInput)
            }

            @DelicateCryptographyApi
            public fun decryptBlocking(iv: ByteArray, ciphertextInput: ByteArray): ByteArray
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
}
