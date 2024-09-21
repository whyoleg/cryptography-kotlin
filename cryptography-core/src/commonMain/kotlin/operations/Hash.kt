/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*
import kotlinx.io.*
import kotlinx.io.bytestring.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Hasher {
    public fun createHashFunction(): HashFunction

    public suspend fun hash(data: ByteArray): ByteArray {
        return hashBlocking(data)
    }

    public suspend fun hash(data: ByteString): ByteString {
        return hash(data.asByteArray()).asByteString()
    }

    public suspend fun hash(data: RawSource): ByteString {
        return hashBlocking(data)
    }

    public fun hashBlocking(data: ByteArray): ByteArray = createHashFunction().use {
        it.update(data)
        it.hashToByteArray()
    }

    public fun hashBlocking(data: ByteString): ByteString {
        return hashBlocking(data.asByteArray()).asByteString()
    }

    public fun hashBlocking(data: RawSource): ByteString = createHashFunction().use {
        it.update(data)
        it.hash()
    }
}

public interface HashFunction : UpdateFunction {
    public fun hashIntoByteArray(destination: ByteArray, destinationOffset: Int = 0): Int
    public fun hashToByteArray(): ByteArray
    public fun hash(): ByteString = hashToByteArray().asByteString()
}
