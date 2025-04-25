/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.primitives.async

import kotlinx.io.*
import kotlinx.io.bytestring.*

public interface HashPrimitive<P> {
    public suspend fun hash(data: ByteString, parameters: P): ByteString
    public suspend fun hash(data: RawSource, parameters: P): ByteString
}
