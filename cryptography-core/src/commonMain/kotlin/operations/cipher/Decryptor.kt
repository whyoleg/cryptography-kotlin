/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations.cipher


import dev.whyoleg.cryptography.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Decryptor {
    public suspend fun decrypt(ciphertext: ByteArray): ByteArray = decryptBlocking(ciphertext)
    public fun decryptBlocking(ciphertext: ByteArray): ByteArray
}
