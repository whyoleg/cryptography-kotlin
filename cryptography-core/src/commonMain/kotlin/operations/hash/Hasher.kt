/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations.hash


import dev.whyoleg.cryptography.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Hasher {
    public suspend fun hash(data: ByteArray): ByteArray = hashBlocking(data)
    public fun hashBlocking(data: ByteArray): ByteArray
}
