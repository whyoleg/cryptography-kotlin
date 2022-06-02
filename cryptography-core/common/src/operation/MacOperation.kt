package dev.whyoleg.cryptography.operation

import dev.whyoleg.vio.*

public interface MacOperation<C, OP, CP> : BufferChunkableOperation<C, OP, CP, MacFunction>

public interface MacFunction : ChunkedOperation {
    public fun update(input: BufferView)
    public fun completeOutputSize(): BinarySize
    public fun complete(input: BufferView, output: BufferView)
}

//Mac | Sing -> Verify ('verify' works both for mac results and signatures)

//mac - symmetric
//sign+verify - asymmetric

//public interface AsyncMacFunction : AsyncBufferFunction {
//    public suspend fun update(input: BufferView)
//    public suspend fun completeOutputSize(): BinarySize
//    public suspend fun complete(input: BufferView, output: BufferView)
//}
