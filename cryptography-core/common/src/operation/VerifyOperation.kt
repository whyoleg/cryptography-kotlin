package dev.whyoleg.cryptography.operation

import dev.whyoleg.vio.*

public interface VerifyOperation<C, OP, CP> :
    ChunkableOperation<C, OP, BufferView, Unit, Boolean, CP, VerifyFunction>

public interface VerifyFunction : ChunkedOperation {
    public fun update(input: BufferView)
    public fun complete(input: BufferView): Boolean
}

//public interface AsyncVerifyOperation<P> :
//    MultiStepAsyncOperation<P, Unit, AsyncVerifyFunction>,
//    SingleStepAsyncOperation<P, BufferView, Unit, Boolean>

//public interface AsyncVerifyFunction : AsyncFunction {
//    public suspend fun update(input: BufferView)
//    public suspend fun complete(input: BufferView): Boolean
//}
