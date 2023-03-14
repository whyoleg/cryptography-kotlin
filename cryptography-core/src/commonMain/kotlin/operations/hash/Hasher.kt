/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations.hash


import dev.whyoleg.cryptography.provider.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Hasher {
    public suspend fun hash(dataInput: ByteArray): ByteArray = hashBlocking(dataInput)
    public fun hashBlocking(dataInput: ByteArray): ByteArray
}
