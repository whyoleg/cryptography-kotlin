/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.functions.*
import kotlinx.io.*
import kotlinx.io.bytestring.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Hasher {
    public fun createHashFunction(): HashFunction

    public suspend fun hash(data: ByteArray): ByteArray = hashBlocking(data)

    public suspend fun hash(data: ByteString): ByteString = hash(data.asByteArray()).asByteString()

    public suspend fun hash(data: RawSource): ByteString = hashBlocking(data)

    public fun hashBlocking(data: ByteArray): ByteArray = createHashFunction().use {
        it.update(data)
        it.hashToByteArray()
    }

    public fun hashBlocking(data: ByteString): ByteString = hashBlocking(data.asByteArray()).asByteString()

    public fun hashBlocking(data: RawSource): ByteString = createHashFunction().use {
        it.updatingSource(data).buffered().transferTo(discardingSink())
        it.hash()
    }
}
