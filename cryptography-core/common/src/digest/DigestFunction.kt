package dev.whyoleg.cryptography.digest

import dev.whyoleg.vio.*

public inline fun <R> Digest.Stream.hash(block: DigestFunction.() -> R): R {
    return createDigestFunction().use(block)
}

public interface DigestFunction : Closeable {
    public val digestSize: BinarySize

    public fun hashPart(input: BufferView)

    public fun hashFinalPart(input: BufferView): BufferView
    public fun hashFinalPart(input: BufferView, digestOutput: BufferView): BufferView
}
