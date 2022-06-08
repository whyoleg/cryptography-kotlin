package dev.whyoleg.cryptography.hash

import dev.whyoleg.vio.*

public interface HashFunction : Closeable {
    public val digestSize: DigestSize

    public fun hashPart(input: BufferView)

    public fun hashFinalPart(input: BufferView): BufferView
    public fun hashFinalPart(input: BufferView, output: BufferView): BufferView
}
