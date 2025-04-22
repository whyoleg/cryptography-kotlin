/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.api.v2.primitives.core

import kotlinx.io.*
import kotlinx.io.bytestring.*

public interface HashPrimitive<P> {
    public fun createHashFunction(parameters: P): HashFunction<P>

    public fun hash(data: ByteString, parameters: P): ByteString
    public fun hash(data: RawSource, parameters: P): ByteString
}

public interface HashFunction<P> : AutoCloseable {
    public fun update(data: ByteString)
    public fun update(data: RawSource)

    public fun updatingSource(data: RawSource): RawSource
    public fun updatingSink(sink: RawSink): RawSink

    public fun reset(parameters: P)
    public fun hash(): ByteString
}
