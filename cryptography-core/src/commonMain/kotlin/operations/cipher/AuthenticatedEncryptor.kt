/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations.cipher


import dev.whyoleg.cryptography.provider.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AuthenticatedEncryptor : Encryptor {
    public suspend fun encrypt(plaintextInput: ByteArray, associatedData: ByteArray?): ByteArray =
        encryptBlocking(plaintextInput, associatedData)

    override suspend fun encrypt(plaintextInput: ByteArray): ByteArray = encrypt(plaintextInput, null)
    public fun encryptBlocking(plaintextInput: ByteArray, associatedData: ByteArray?): ByteArray
    override fun encryptBlocking(plaintextInput: ByteArray): ByteArray = encryptBlocking(plaintextInput, null)
}
