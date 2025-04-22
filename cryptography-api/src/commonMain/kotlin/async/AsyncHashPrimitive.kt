/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.api.async

import dev.whyoleg.cryptography.api.*
import kotlinx.io.*
import kotlinx.io.bytestring.*

public interface AsyncHashPrimitive<P> : CryptographyPrimitive {
    public suspend fun hash(data: ByteString, parameters: P): ByteString
    public suspend fun hash(data: RawSource, parameters: P): ByteString
}

@Suppress("NOTHING_TO_INLINE")
public suspend inline fun AsyncHashPrimitive<Unit>.hash(data: ByteString): ByteString = hash(data, Unit)
