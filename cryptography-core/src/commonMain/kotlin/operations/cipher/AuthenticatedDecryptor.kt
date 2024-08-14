/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations.cipher


import dev.whyoleg.cryptography.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AuthenticatedDecryptor : Decryptor {
    public suspend fun decrypt(ciphertext: ByteArray, associatedData: ByteArray?): ByteArray =
        decryptBlocking(ciphertext, associatedData)

    override suspend fun decrypt(ciphertext: ByteArray): ByteArray = decrypt(ciphertext, null)
    public fun decryptBlocking(ciphertext: ByteArray, associatedData: ByteArray?): ByteArray
    override fun decryptBlocking(ciphertext: ByteArray): ByteArray = decryptBlocking(ciphertext, null)
}
