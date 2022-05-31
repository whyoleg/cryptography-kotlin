package dev.whyoleg.cryptography.hm.cipher

import dev.whyoleg.cryptography.hm.*
import dev.whyoleg.vio.*

public interface CipherFunction : CryptographyFunction {
    public fun transformOutputSize(inputSize: BinarySize): BinarySize
    public fun transform(input: BufferView, output: BufferView)

    public fun completeOutputSize(inputSize: BinarySize): BinarySize
    public fun complete(input: BufferView, output: BufferView)

    public interface Async : CryptographyFunction {
        public suspend fun transformOutputSize(inputSize: BinarySize): BinarySize
        public suspend fun transform(input: BufferView, output: BufferView)

        public suspend fun completeOutputSize(inputSize: BinarySize): BinarySize
        public suspend fun complete(input: BufferView, output: BufferView)
    }
}