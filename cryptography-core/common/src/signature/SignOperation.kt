package dev.whyoleg.cryptography.signature

import dev.whyoleg.vio.*

public interface SignOperation {
    public fun createFunction(): SignFunction
    public fun outputSize(inputSize: BinarySize): BinarySize
    public operator fun invoke(input: BufferView): BufferView
    public operator fun invoke(input: BufferView, output: BufferView): BufferView
    public operator fun <R> invoke(block: SignFunction.() -> R): R //TODO: ext
}

public interface SignFunction : Closeable {
    public fun update(input: BufferView)

    //what size will be if on complete with provided inputSize //TODO?????
    public fun completeOutputSize(inputSize: BinarySize): BinarySize
    public fun complete(input: BufferView, output: BufferView)
}
