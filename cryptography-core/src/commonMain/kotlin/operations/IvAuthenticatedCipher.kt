/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*
import kotlinx.io.*
import kotlinx.io.bytestring.*

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
