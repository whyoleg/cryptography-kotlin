package dev.whyoleg.cryptography.operation

import dev.whyoleg.vio.*

public interface SignOperation<C, OP, CP> : BufferChunkableOperation<C, OP, CP, SignFunction>

public interface SignFunction : ChunkedOperation {
    public fun update(input: BufferView)
    public fun completeOutputSize(): BinarySize
    public fun complete(input: BufferView, output: BufferView)
}

//public interface AsyncSignFunction : AsyncBufferFunction {
//    public suspend fun update(input: BufferView)
//    public suspend fun completeOutputSize(): BinarySize
//    public suspend fun complete(input: BufferView, output: BufferView)
//}
//