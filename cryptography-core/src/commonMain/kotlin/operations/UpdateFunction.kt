/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*
import kotlinx.io.*
import kotlinx.io.bytestring.*
import kotlinx.io.unsafe.*

/**
 * Base interface for incremental (streaming) cryptographic operations such as hashing and signing.
 *
 * Data should be fed incrementally via [update], and the result could be obtained from a subtype-specific finalization method.
 * Should be [closed][close] after use to release resources.
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface UpdateFunction : AutoCloseable {
    /**
     * Resets the accumulated state, allowing this function to be reused for a new operation
     * without creating a new instance.
     */
    public fun reset()

    /**
     * Feeds data from the [source] byte array into this function.
     * Only the portion from [startIndex] (inclusive) to [endIndex] (exclusive) is processed.
     */
    public fun update(source: ByteArray, startIndex: Int = 0, endIndex: Int = source.size)

    /**
     * Feeds data from the [source] byte string into this function.
     * Only the portion from [startIndex] (inclusive) to [endIndex] (exclusive) is processed.
     */
    public fun update(source: ByteString, startIndex: Int = 0, endIndex: Int = source.size) {
        update(source.asByteArray(), startIndex, endIndex)
    }

    /**
     * Reads all available data from the [source] and feeds it into this function.
     */
    public fun update(source: RawSource) {
        updatingSource(source).buffered().transferTo(discardingSink())
    }

    /**
     * Returns a [RawSource] wrapper around the given [source] that feeds all data read through it
     * into this function as a side effect. Useful for processing data from a source while
     * simultaneously computing a hash or signature.
     *
     * Use [updatingSink] to wrap a sink instead.
     */
    public fun updatingSource(source: RawSource): RawSource {
        return UpdatingSource(source, this)
    }

    /**
     * Returns a [RawSink] wrapper around the given [sink] that feeds all data written through it
     * into this function as a side effect. Useful for writing data to a sink while
     * simultaneously computing a hash or signature.
     *
     * Use [updatingSource] to wrap a source instead.
     */
    public fun updatingSink(sink: RawSink): RawSink {
        return UpdatingSink(sink, this)
    }
}

// TODO: add tests for this changes
@OptIn(UnsafeIoApi::class)
private class UpdatingSource(
    private val source: RawSource,
    private val function: UpdateFunction,
) : RawSource {
    override fun readAtMostTo(sink: Buffer, byteCount: Long): Long {
        val bytesRead = source.readAtMostTo(sink, byteCount)
        if (bytesRead != -1L) {
            val sinkOffset = sink.size - bytesRead
            UnsafeBufferOperations.iterate(sink, sinkOffset) { context, head, headOffset ->
                var segment = head
                // needed only for head segment
                var additionalOffset = (sinkOffset - headOffset).toInt()
                while (segment != null) {
                    context.withData(segment) { data, startIndex, endIndex ->
                        function.update(data, startIndex + additionalOffset, endIndex)
                    }
                    segment = context.next(segment)
                    additionalOffset = 0
                }
            }
        }
        return bytesRead
    }

    override fun close(): Unit = source.close()
}

@OptIn(UnsafeIoApi::class)
private class UpdatingSink(
    private val sink: RawSink,
    private val function: UpdateFunction,
) : RawSink {
    override fun write(source: Buffer, byteCount: Long) {
        source.require(byteCount)

        UnsafeBufferOperations.iterate(source) { context, head ->
            var remaining = byteCount
            var segment = head
            while (segment != null && remaining > 0) {
                context.withData(segment) { bytes, startIndex, endIndex ->
                    val toUpdate = minOf(remaining, (endIndex - startIndex).toLong()).toInt()
                    function.update(bytes, startIndex, startIndex + toUpdate)
                    remaining -= toUpdate
                }
                segment = context.next(segment)
            }
        }

        sink.write(source, byteCount)
    }

    override fun flush(): Unit = sink.flush()
    override fun close(): Unit = sink.close()
}
