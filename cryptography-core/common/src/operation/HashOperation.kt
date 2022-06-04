package dev.whyoleg.cryptography.operation

import dev.whyoleg.vio.*

public interface HashOperation<C, OP, CP> :
    BufferChunkableOperation<C, OP, CP, HashFunction>

public interface HashFunction : ChunkedOperation {
    public fun update(input: BufferView)
    public fun completeOutputSize(): BinarySize
    public fun complete(input: BufferView, output: BufferView)
}

//public interface AsyncHashFunction : AsyncFunction {
//    public suspend fun update(input: BufferView)
//    public suspend fun completeOutputSize(): BinarySize
//    public suspend fun complete(input: BufferView, output: BufferView)
//}
