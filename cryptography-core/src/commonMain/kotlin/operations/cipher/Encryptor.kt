/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations.cipher


import dev.whyoleg.cryptography.provider.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Encryptor {
    public suspend fun encrypt(plaintextInput: ByteArray): ByteArray = encryptBlocking(plaintextInput)
    public fun encryptBlocking(plaintextInput: ByteArray): ByteArray
}
