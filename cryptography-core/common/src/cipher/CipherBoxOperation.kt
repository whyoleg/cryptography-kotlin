package dev.whyoleg.cryptography.cipher

import dev.whyoleg.vio.*

public interface EncryptBoxOperation<C, OP, B : CipherBox, CP, F : CipherBoxFunction<*, *>> :
    BufferOutputChunkableOperation<C, OP, BufferView, B, CP, F>

public interface DecryptBoxOperation<C, OP, B : CipherBox, CP, F : CipherBoxFunction<*, *>> :
    BufferOutputChunkableOperation<C, OP, B, BufferView, CP, F>

//TODO: proper name
public abstract class CipherBox(public val ciphertext: BufferView)

public interface CipherBoxFunction<CP, CR> : Closeable {
    public fun transformOutputSize(inputSize: BinarySize): BinarySize
    public fun transform(input: BufferView, output: BufferView)

    public fun completeOutputSize(inputSize: BinarySize): BinarySize
    public fun complete(input: BufferView, output: BufferView, parameters: CP): CR
}
