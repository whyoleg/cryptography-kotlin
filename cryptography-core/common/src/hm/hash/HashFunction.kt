package dev.whyoleg.cryptography.hm.hash

import dev.whyoleg.cryptography.hm.*
import dev.whyoleg.vio.*

public interface HashFunction : CryptographyFunction {
    public fun update(input: BufferView)
    public fun completeOutputSize(): BinarySize
    public fun complete(input: BufferView, output: BufferView)

    public interface Async : CryptographyFunction {
        public suspend fun update(input: BufferView)
        public suspend fun completeOutputSize(): BinarySize
        public suspend fun complete(input: BufferView, output: BufferView)
    }
}
