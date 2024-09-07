/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*
import kotlinx.io.bytestring.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Cipher : Encryptor, Decryptor

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Encryptor {
    public suspend fun encrypt(plaintext: ByteArray): ByteArray = encryptBlocking(plaintext)
    public fun encryptBlocking(plaintext: ByteArray): ByteArray

    public suspend fun encrypt(plaintext: ByteString): ByteString = encrypt(plaintext.asByteArray()).asByteString()
    public fun encryptBlocking(plaintext: ByteString): ByteString = encryptBlocking(plaintext.asByteArray()).asByteString()
}

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Decryptor {
    public suspend fun decrypt(ciphertext: ByteArray): ByteArray = decryptBlocking(ciphertext)
    public fun decryptBlocking(ciphertext: ByteArray): ByteArray

    public suspend fun decrypt(ciphertext: ByteString): ByteString = decrypt(ciphertext.asByteArray()).asByteString()
    public fun decryptBlocking(ciphertext: ByteString): ByteString = decryptBlocking(ciphertext.asByteArray()).asByteString()
}
