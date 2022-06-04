package dev.whyoleg.cryptography.operation

import dev.whyoleg.vio.*

public interface CipherOperation<C, OP, CP> :
    BufferChunkableOperation<C, OP, CP, CipherFunction>

public interface CipherFunction : ChunkedOperation {
    public fun transformOutputSize(inputSize: BinarySize): BinarySize
    public fun transform(input: BufferView, output: BufferView)

    public fun completeOutputSize(inputSize: BinarySize): BinarySize
    public fun complete(input: BufferView, output: BufferView)
}
