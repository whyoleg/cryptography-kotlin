/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*
import kotlinx.io.*
import kotlinx.io.bytestring.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AuthenticatedCipher : Cipher, AuthenticatedEncryptor, AuthenticatedDecryptor

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AuthenticatedEncryptor : Encryptor {
    public override suspend fun encrypt(plaintext: ByteArray): ByteArray {
        return encrypt(plaintext, null)
    }

    public override suspend fun encrypt(plaintext: ByteString): ByteString {
        return encrypt(plaintext, null)
    }

    public suspend fun encrypt(plaintext: ByteArray, associatedData: ByteArray?): ByteArray {
        return encryptBlocking(plaintext, associatedData)
    }

    public suspend fun encrypt(plaintext: ByteString, associatedData: ByteString?): ByteString {
        return encrypt(plaintext.asByteArray(), associatedData?.asByteArray()).asByteString()
    }


    public override fun encryptBlocking(plaintext: ByteArray): ByteArray {
        return encryptBlocking(plaintext, null)
    }

    public override fun encryptBlocking(plaintext: ByteString): ByteString {
        return encryptBlocking(plaintext, null)
    }

    public fun encryptBlocking(plaintext: ByteArray, associatedData: ByteArray?): ByteArray

    public fun encryptBlocking(plaintext: ByteString, associatedData: ByteString?): ByteString {
        return encryptBlocking(plaintext.asByteArray(), associatedData?.asByteArray()).asByteString()
    }


    public override fun encryptingSource(plaintext: RawSource): RawSource {
        return encryptingSource(plaintext, null as ByteArray?)
    }

    public fun encryptingSource(plaintext: RawSource, associatedData: ByteArray?): RawSource

    public fun encryptingSource(plaintext: RawSource, associatedData: ByteString?): RawSource {
        return encryptingSource(plaintext, associatedData?.asByteArray())
    }


    public override fun encryptingSink(ciphertext: RawSink): RawSink {
        return encryptingSink(ciphertext, null as ByteArray?)
    }

    public fun encryptingSink(ciphertext: RawSink, associatedData: ByteArray?): RawSink

    public fun encryptingSink(ciphertext: RawSink, associatedData: ByteString?): RawSink {
        return encryptingSink(ciphertext, associatedData?.asByteArray())
    }
}

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AuthenticatedDecryptor : Decryptor {

    public override suspend fun decrypt(ciphertext: ByteArray): ByteArray {
        return decrypt(ciphertext, null)
    }

    public override suspend fun decrypt(ciphertext: ByteString): ByteString {
        return decrypt(ciphertext, null)
    }

    public suspend fun decrypt(ciphertext: ByteArray, associatedData: ByteArray?): ByteArray {
        return decryptBlocking(ciphertext, associatedData)
    }

    public suspend fun decrypt(ciphertext: ByteString, associatedData: ByteString?): ByteString {
        return decrypt(ciphertext.asByteArray(), associatedData?.asByteArray()).asByteString()
    }


    public override fun decryptBlocking(ciphertext: ByteArray): ByteArray {
        return decryptBlocking(ciphertext, null)
    }

    public override fun decryptBlocking(ciphertext: ByteString): ByteString {
        return decryptBlocking(ciphertext, null)
    }

    public fun decryptBlocking(ciphertext: ByteArray, associatedData: ByteArray?): ByteArray

    public fun decryptBlocking(ciphertext: ByteString, associatedData: ByteString?): ByteString {
        return decryptBlocking(ciphertext.asByteArray(), associatedData?.asByteArray()).asByteString()
    }


    public override fun decryptingSource(ciphertext: RawSource): RawSource {
        return decryptingSource(ciphertext, null as ByteArray?)
    }

    public fun decryptingSource(ciphertext: RawSource, associatedData: ByteArray?): RawSource

    public fun decryptingSource(ciphertext: RawSource, associatedData: ByteString?): RawSource {
        return decryptingSource(ciphertext, associatedData?.asByteArray())
    }


    public override fun decryptingSink(plaintext: RawSink): RawSink {
        return decryptingSink(plaintext, null as ByteArray?)
    }

    public fun decryptingSink(plaintext: RawSink, associatedData: ByteArray?): RawSink

    public fun decryptingSink(plaintext: RawSink, associatedData: ByteString?): RawSink {
        return decryptingSink(plaintext, associatedData?.asByteArray())
    }
}
