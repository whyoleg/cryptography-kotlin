/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*
import kotlinx.io.*
import kotlinx.io.bytestring.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Cipher : Encryptor, Decryptor

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Encryptor {
    public suspend fun encrypt(plaintext: ByteArray): ByteArray {
        return encryptBlocking(plaintext)
    }

    public suspend fun encrypt(plaintext: ByteString): ByteString {
        return encrypt(plaintext.asByteArray()).asByteString()
    }

    public fun encryptBlocking(plaintext: ByteArray): ByteArray

    public fun encryptBlocking(plaintext: ByteString): ByteString {
        return encryptBlocking(plaintext.asByteArray()).asByteString()
    }

    public fun encryptingSource(plaintext: RawSource): RawSource

    public fun encryptingSink(ciphertext: RawSink): RawSink
}

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Decryptor {
    public suspend fun decrypt(ciphertext: ByteArray): ByteArray {
        return decryptBlocking(ciphertext)
    }

    public suspend fun decrypt(ciphertext: ByteString): ByteString {
        return decrypt(ciphertext.asByteArray()).asByteString()
    }

    public fun decryptBlocking(ciphertext: ByteArray): ByteArray

    public fun decryptBlocking(ciphertext: ByteString): ByteString {
        return decryptBlocking(ciphertext.asByteArray()).asByteString()
    }

    public fun decryptingSource(ciphertext: RawSource): RawSource

    public fun decryptingSink(plaintext: RawSink): RawSink
}
