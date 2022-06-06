package dev.whyoleg.cryptography.hash

import dev.whyoleg.vio.*

public interface HashFunction : Closeable {
    public val digestSize: DigestSize

    public fun update(input: BufferView)

    public fun complete(input: BufferView): BufferView
    public fun complete(input: BufferView, output: BufferView): BufferView
}
