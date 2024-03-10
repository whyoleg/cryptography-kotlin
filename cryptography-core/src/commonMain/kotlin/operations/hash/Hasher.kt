/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations.hash

import dev.whyoleg.cryptography.*
import kotlinx.io.*
import kotlinx.io.bytestring.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Hasher {
    public suspend fun hash(data: ByteArray): ByteArray = hashBlocking(data)
    public fun hashBlocking(data: ByteArray): ByteArray

    @ExperimentalCryptographyIoApi
    public suspend fun hash(data: ByteString): ByteString

    @ExperimentalCryptographyIoApi
    public fun hashBlocking(data: ByteString): ByteString

    // depending on implementation, returned sources could contain full result or will be streamed
    @ExperimentalCryptographyIoApi
    public suspend fun hash(data: Source): Source

    @ExperimentalCryptographyIoApi
    public fun hashBlocking(data: Source): Source
}
