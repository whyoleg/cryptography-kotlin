/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations.cipher

import dev.whyoleg.cryptography.*
import kotlinx.io.bytestring.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface AuthenticatedEncryptor : Encryptor {
    public suspend fun encrypt(plaintext: ByteArray, associatedData: ByteArray?): ByteArray = encryptBlocking(plaintext, associatedData)
    public fun encryptBlocking(plaintext: ByteArray, associatedData: ByteArray?): ByteArray

    public override suspend fun encrypt(plaintext: ByteArray): ByteArray = encrypt(plaintext, null)
    public override fun encryptBlocking(plaintext: ByteArray): ByteArray = encryptBlocking(plaintext, null)

    public suspend fun encrypt(plaintext: ByteString, associatedData: ByteString?): ByteString =
        encrypt(plaintext.asByteArray(), associatedData?.asByteArray()).asByteString()

    public fun encryptBlocking(plaintext: ByteString, associatedData: ByteString?): ByteString =
        encryptBlocking(plaintext.asByteArray(), associatedData?.asByteArray()).asByteString()

    public override suspend fun encrypt(plaintext: ByteString): ByteString = encrypt(plaintext, null)
    public override fun encryptBlocking(plaintext: ByteString): ByteString = encryptBlocking(plaintext, null)
}
