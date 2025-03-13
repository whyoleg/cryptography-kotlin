/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.primitives.core

import kotlinx.io.*
import kotlinx.io.bytestring.*

public interface AccumulatingFunction : AutoCloseable {
    public fun update(data: ByteString)
    public fun update(data: RawSource)

    public fun updatingSource(data: RawSource): RawSource
    public fun updatingSink(sink: RawSink): RawSink

    public fun reset()
}
