/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations.cipher


import dev.whyoleg.cryptography.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AuthenticatedEncryptor : Encryptor {
    public suspend fun encrypt(plaintext: ByteArray, associatedData: ByteArray?): ByteArray =
        encryptBlocking(plaintext, associatedData)

    override suspend fun encrypt(plaintext: ByteArray): ByteArray = encrypt(plaintext, null)
    public fun encryptBlocking(plaintext: ByteArray, associatedData: ByteArray?): ByteArray
    override fun encryptBlocking(plaintext: ByteArray): ByteArray = encryptBlocking(plaintext, null)
}
