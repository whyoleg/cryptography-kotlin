/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.functions

import dev.whyoleg.cryptography.*
import kotlinx.io.*
import kotlinx.io.bytestring.*
import kotlinx.io.unsafe.*

public interface UpdateFunction : AutoCloseable {
    public fun update(source: ByteArray, startIndex: Int = 0, endIndex: Int = source.size)
    public fun update(source: ByteString, startIndex: Int = 0, endIndex: Int = source.size) {
        update(source.asByteArray(), startIndex, endIndex)
    }

    public fun update(source: RawSource) {
        updatingSource(source).buffered().transferTo(discardingSink())
    }

    public fun updatingSource(source: RawSource): RawSource = UpdatingSource(this, source)
    public fun updatingSink(sink: RawSink): RawSink = UpdatingSink(this, sink)
}

private class UpdatingSource(
    private val function: UpdateFunction,
    private val source: RawSource,
) : RawSource {
    override fun readAtMostTo(sink: Buffer, byteCount: Long): Long {
        val result = source.readAtMostTo(sink, byteCount)
        if (result != -1L) {
            @OptIn(UnsafeIoApi::class)
            UnsafeBufferOperations.iterate(sink, sink.size - result) { context, head, _ ->
                var segment = head
                while (segment != null) {
                    context.withData(segment, function::update)
                    segment = context.next(segment)
                }
            }
        }
        return result
    }

    override fun close(): Unit = source.close()
}

private class UpdatingSink(
    private val function: UpdateFunction,
    private val sink: RawSink,
) : RawSink {
    override fun write(source: Buffer, byteCount: Long) {
        source.require(byteCount)

        @OptIn(UnsafeIoApi::class)
        UnsafeBufferOperations.iterate(source) { context, head ->
            var consumedCount = 0L
            var segment = head
            while (segment != null && consumedCount < byteCount) {
                context.withData(segment) { bytes, startIndex, endIndex ->
                    val toUpdate = minOf(byteCount - consumedCount, (endIndex - startIndex).toLong()).toInt()
                    function.update(bytes, startIndex, startIndex + toUpdate)
                    consumedCount += toUpdate
                }
                segment = context.next(segment)
            }
        }

        sink.write(source, byteCount)
    }

    override fun flush(): Unit = sink.flush()
    override fun close(): Unit = sink.close()
}
