package dev.whyoleg.cryptography.signature

import dev.whyoleg.cryptography.new.*
import dev.whyoleg.vio.*

public interface Signer : CryptographyPrimitive {
    public interface Sync : Signer {
        public val signatureSize: BinarySize

        public fun sign(input: BufferView): BufferView
        public fun sign(input: BufferView, output: BufferView): BufferView
    }

    public interface Async : Signer {
        public val signatureSize: BinarySize

        public suspend fun sign(input: BufferView): BufferView
        public suspend fun sign(input: BufferView, output: BufferView): BufferView
    }

    public interface Stream : Signer {
        public fun createSignFunction(): SignFunction
    }
}
