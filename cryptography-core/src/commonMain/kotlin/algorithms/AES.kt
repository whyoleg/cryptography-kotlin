/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.materials.key.*
import dev.whyoleg.cryptography.operations.*
import kotlinx.io.*
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
    public interface CMAC : AES<CMAC.Key> {
        override val id: CryptographyAlgorithmId<CMAC> get() = Companion

        public companion object : CryptographyAlgorithmId<CMAC>("AES-CMAC")

        @SubclassOptInRequired(CryptographyProviderApi::class)
        public interface Key : AES.Key {
            public fun signatureGenerator(): SignatureGenerator
            public fun signatureVerifier(): SignatureVerifier
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
            public fun cipher(tagSize: BinarySize = 128.bits): IvAuthenticatedCipher
        }
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface IvCipher : Cipher, IvEncryptor, IvDecryptor

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface IvEncryptor : Encryptor {
        @DelicateCryptographyApi
        public suspend fun encryptWithIv(iv: ByteArray, plaintext: ByteArray): ByteArray {
            return encryptWithIvBlocking(iv, plaintext)
        }

        @DelicateCryptographyApi
        public suspend fun encryptWithIv(iv: ByteString, plaintext: ByteString): ByteString {
            return encryptWithIv(iv.asByteArray(), plaintext.asByteArray()).asByteString()
        }

        @DelicateCryptographyApi
        public fun encryptWithIvBlocking(iv: ByteArray, plaintext: ByteArray): ByteArray

        @DelicateCryptographyApi
        public fun encryptWithIvBlocking(iv: ByteString, plaintext: ByteString): ByteString {
            return encryptWithIvBlocking(iv.asByteArray(), plaintext.asByteArray()).asByteString()
        }


        @DelicateCryptographyApi
        public fun encryptingSourceWithIv(iv: ByteArray, plaintext: RawSource): RawSource

        @DelicateCryptographyApi
        public fun encryptingSourceWithIv(iv: ByteString, plaintext: RawSource): RawSource {
            return encryptingSourceWithIv(iv.asByteArray(), plaintext)
        }


        @DelicateCryptographyApi
        public fun encryptingSinkWithIv(iv: ByteArray, ciphertext: RawSink): RawSink

        @DelicateCryptographyApi
        public fun encryptingSinkWithIv(iv: ByteString, ciphertext: RawSink): RawSink {
            return encryptingSinkWithIv(iv.asByteArray(), ciphertext)
        }
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface IvDecryptor : Decryptor {
        @DelicateCryptographyApi
        public suspend fun decryptWithIv(iv: ByteArray, ciphertext: ByteArray): ByteArray {
            return decryptWithIvBlocking(iv, ciphertext)
        }

        @DelicateCryptographyApi
        public suspend fun decryptWithIv(iv: ByteString, ciphertext: ByteString): ByteString {
            return decryptWithIv(iv.asByteArray(), ciphertext.asByteArray()).asByteString()
        }

        @DelicateCryptographyApi
        public fun decryptWithIvBlocking(iv: ByteArray, ciphertext: ByteArray): ByteArray

        @DelicateCryptographyApi
        public fun decryptWithIvBlocking(iv: ByteString, ciphertext: ByteString): ByteString {
            return decryptWithIvBlocking(iv.asByteArray(), ciphertext.asByteArray()).asByteString()
        }


        @DelicateCryptographyApi
        public fun decryptingSourceWithIv(iv: ByteArray, ciphertext: RawSource): RawSource

        @DelicateCryptographyApi
        public fun decryptingSourceWithIv(iv: ByteString, ciphertext: RawSource): RawSource {
            return decryptingSourceWithIv(iv.asByteArray(), ciphertext)
        }


        @DelicateCryptographyApi
        public fun decryptingSinkWithIv(iv: ByteArray, plaintext: RawSink): RawSink

        @DelicateCryptographyApi
        public fun decryptingSinkWithIv(iv: ByteString, plaintext: RawSink): RawSink {
            return decryptingSinkWithIv(iv.asByteArray(), plaintext)
        }
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface IvAuthenticatedCipher : IvCipher, AuthenticatedCipher, IvAuthenticatedEncryptor, IvAuthenticatedDecryptor

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface IvAuthenticatedEncryptor : IvEncryptor, AuthenticatedEncryptor {
        @DelicateCryptographyApi
        override suspend fun encryptWithIv(iv: ByteArray, plaintext: ByteArray): ByteArray {
            return encryptWithIv(iv, plaintext, null)
        }

        @DelicateCryptographyApi
        override suspend fun encryptWithIv(iv: ByteString, plaintext: ByteString): ByteString {
            return encryptWithIv(iv, plaintext, null)
        }

        @DelicateCryptographyApi
        public suspend fun encryptWithIv(iv: ByteArray, plaintext: ByteArray, associatedData: ByteArray?): ByteArray {
            return encryptWithIvBlocking(iv, plaintext, associatedData)
        }

        @DelicateCryptographyApi
        public suspend fun encryptWithIv(iv: ByteString, plaintext: ByteString, associatedData: ByteString?): ByteString {
            return encryptWithIv(iv.asByteArray(), plaintext.asByteArray(), associatedData?.toByteArray()).asByteString()
        }

        @DelicateCryptographyApi
        override fun encryptWithIvBlocking(iv: ByteArray, plaintext: ByteArray): ByteArray {
            return encryptWithIvBlocking(iv, plaintext, null)
        }

        @DelicateCryptographyApi
        override fun encryptWithIvBlocking(iv: ByteString, plaintext: ByteString): ByteString {
            return encryptWithIvBlocking(iv, plaintext, null)
        }

        @DelicateCryptographyApi
        public fun encryptWithIvBlocking(iv: ByteArray, plaintext: ByteArray, associatedData: ByteArray?): ByteArray

        @DelicateCryptographyApi
        public fun encryptWithIvBlocking(iv: ByteString, plaintext: ByteString, associatedData: ByteString?): ByteString {
            return encryptWithIvBlocking(iv.asByteArray(), plaintext.asByteArray(), associatedData?.toByteArray()).asByteString()
        }


        @DelicateCryptographyApi
        override fun encryptingSourceWithIv(iv: ByteArray, plaintext: RawSource): RawSource {
            return encryptingSourceWithIv(iv, plaintext, null)
        }

        @DelicateCryptographyApi
        public fun encryptingSourceWithIv(iv: ByteArray, plaintext: RawSource, associatedData: ByteArray?): RawSource

        @DelicateCryptographyApi
        public fun encryptingSourceWithIv(iv: ByteString, plaintext: RawSource, associatedData: ByteString?): RawSource {
            return encryptingSourceWithIv(iv.asByteArray(), plaintext, associatedData?.asByteArray())
        }


        @DelicateCryptographyApi
        override fun encryptingSinkWithIv(iv: ByteArray, ciphertext: RawSink): RawSink {
            return encryptingSinkWithIv(iv, ciphertext, null)
        }

        @DelicateCryptographyApi
        public fun encryptingSinkWithIv(iv: ByteArray, ciphertext: RawSink, associatedData: ByteArray?): RawSink

        @DelicateCryptographyApi
        public fun encryptingSinkWithIv(iv: ByteString, ciphertext: RawSink, associatedData: ByteString?): RawSink {
            return encryptingSinkWithIv(iv.asByteArray(), ciphertext, associatedData?.toByteArray())
        }
    }

    @SubclassOptInRequired(CryptographyProviderApi::class)
    public interface IvAuthenticatedDecryptor : IvDecryptor, AuthenticatedDecryptor {

        @DelicateCryptographyApi
        override suspend fun decryptWithIv(iv: ByteArray, ciphertext: ByteArray): ByteArray {
            return decryptWithIv(iv, ciphertext, null)
        }

        @DelicateCryptographyApi
        override suspend fun decryptWithIv(iv: ByteString, ciphertext: ByteString): ByteString {
            return decryptWithIv(iv, ciphertext, null)
        }

        @DelicateCryptographyApi
        public suspend fun decryptWithIv(iv: ByteArray, ciphertext: ByteArray, associatedData: ByteArray?): ByteArray {
            return decryptWithIvBlocking(iv, ciphertext, associatedData)
        }

        @DelicateCryptographyApi
        public suspend fun decryptWithIv(iv: ByteString, ciphertext: ByteString, associatedData: ByteString?): ByteString {
            return decryptWithIv(iv.asByteArray(), ciphertext.asByteArray(), associatedData?.toByteArray()).asByteString()
        }

        @DelicateCryptographyApi
        override fun decryptWithIvBlocking(iv: ByteArray, ciphertext: ByteArray): ByteArray {
            return decryptWithIvBlocking(iv, ciphertext, null)
        }

        @DelicateCryptographyApi
        override fun decryptWithIvBlocking(iv: ByteString, ciphertext: ByteString): ByteString {
            return decryptWithIvBlocking(iv, ciphertext, null)
        }

        @DelicateCryptographyApi
        public fun decryptWithIvBlocking(iv: ByteArray, ciphertext: ByteArray, associatedData: ByteArray?): ByteArray

        @DelicateCryptographyApi
        public fun decryptWithIvBlocking(iv: ByteString, ciphertext: ByteString, associatedData: ByteString?): ByteString {
            return decryptWithIvBlocking(iv.asByteArray(), ciphertext.asByteArray(), associatedData?.toByteArray()).asByteString()
        }


        @DelicateCryptographyApi
        override fun decryptingSourceWithIv(iv: ByteArray, ciphertext: RawSource): RawSource {
            return decryptingSourceWithIv(iv, ciphertext, null)
        }

        @DelicateCryptographyApi
        public fun decryptingSourceWithIv(iv: ByteArray, plaintext: RawSource, associatedData: ByteArray?): RawSource

        @DelicateCryptographyApi
        public fun decryptingSourceWithIv(iv: ByteString, plaintext: RawSource, associatedData: ByteString?): RawSource {
            return decryptingSourceWithIv(iv.asByteArray(), plaintext, associatedData?.asByteArray())
        }


        @DelicateCryptographyApi
        override fun decryptingSinkWithIv(iv: ByteArray, plaintext: RawSink): RawSink {
            return decryptingSinkWithIv(iv, plaintext, null)
        }

        @DelicateCryptographyApi
        public fun decryptingSinkWithIv(iv: ByteArray, ciphertext: RawSink, associatedData: ByteArray?): RawSink

        @DelicateCryptographyApi
        public fun decryptingSinkWithIv(iv: ByteString, ciphertext: RawSink, associatedData: ByteString?): RawSink {
            return decryptingSinkWithIv(iv.asByteArray(), ciphertext, associatedData?.toByteArray())
        }
    }
}
