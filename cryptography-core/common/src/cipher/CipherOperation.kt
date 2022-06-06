package dev.whyoleg.cryptography.cipher

import dev.whyoleg.vio.*

public interface CipherOperation {
    public fun outputSize(inputSize: BinarySize): BinarySize

    public fun createFunction(): CipherFunction

    public operator fun invoke(input: BufferView): BufferView
    public operator fun invoke(input: BufferView, output: BufferView): BufferView
}

public inline operator fun <R> CipherOperation.invoke(block: CipherFunction.() -> R): R {
    return createFunction().use(block)
}


public interface CipherFunction : Closeable {
    public fun transformOutputSize(inputSize: BinarySize): BinarySize
    public fun transform(input: BufferView): BufferView
    public fun transform(input: BufferView, output: BufferView): BufferView

    public fun completeOutputSize(inputSize: BinarySize): BinarySize
    public fun complete(input: BufferView): BufferView
    public fun complete(input: BufferView, output: BufferView): BufferView
}
