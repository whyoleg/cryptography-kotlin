/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations.cipher


import dev.whyoleg.cryptography.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AuthenticatedDecryptor : Decryptor {
    public suspend fun decrypt(ciphertextInput: ByteArray, associatedData: ByteArray?): ByteArray =
        decryptBlocking(ciphertextInput, associatedData)

    override suspend fun decrypt(ciphertextInput: ByteArray): ByteArray = decrypt(ciphertextInput, null)
    public fun decryptBlocking(ciphertextInput: ByteArray, associatedData: ByteArray?): ByteArray
    override fun decryptBlocking(ciphertextInput: ByteArray): ByteArray = decryptBlocking(ciphertextInput, null)
}
