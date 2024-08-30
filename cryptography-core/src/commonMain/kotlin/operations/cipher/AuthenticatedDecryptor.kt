/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations.cipher

import dev.whyoleg.cryptography.*
import kotlinx.io.bytestring.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AuthenticatedDecryptor : Decryptor {
    public suspend fun decrypt(ciphertext: ByteArray, associatedData: ByteArray?): ByteArray = decryptBlocking(ciphertext, associatedData)
    public fun decryptBlocking(ciphertext: ByteArray, associatedData: ByteArray?): ByteArray

    public override suspend fun decrypt(ciphertext: ByteArray): ByteArray = decrypt(ciphertext, null)
    public override fun decryptBlocking(ciphertext: ByteArray): ByteArray = decryptBlocking(ciphertext, null)

    public suspend fun decrypt(ciphertext: ByteString, associatedData: ByteString?): ByteString =
        decrypt(ciphertext.asByteArray(), associatedData?.asByteArray()).asByteString()

    public fun decryptBlocking(ciphertext: ByteString, associatedData: ByteString?): ByteString =
        decryptBlocking(ciphertext.asByteArray(), associatedData?.asByteArray()).asByteString()

    public override suspend fun decrypt(ciphertext: ByteString): ByteString = decrypt(ciphertext, null)
    public override fun decryptBlocking(ciphertext: ByteString): ByteString = decryptBlocking(ciphertext, null)
}
