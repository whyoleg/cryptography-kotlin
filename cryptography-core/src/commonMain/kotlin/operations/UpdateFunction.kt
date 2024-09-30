/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*
import kotlinx.io.*
import kotlinx.io.bytestring.*
import kotlinx.io.unsafe.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface UpdateFunction : AutoCloseable {
    public fun update(source: ByteArray, startIndex: Int = 0, endIndex: Int = source.size)
    public fun update(source: ByteString, startIndex: Int = 0, endIndex: Int = source.size) {
        update(source.asByteArray(), startIndex, endIndex)
    }

    public fun update(source: RawSource) {
        updatingSource(source).buffered().transferTo(discardingSink())
    }

    public fun updatingSource(source: RawSource): RawSource {
        return UpdatingSource(source, this)
    }

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
