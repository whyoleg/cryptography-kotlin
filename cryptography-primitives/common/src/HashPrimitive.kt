package dev.whyoleg.cryptography.primitives

import dev.whyoleg.cryptography.*
import dev.whyoleg.vio.*

//TODO: better name?
public interface HashPrimitive {
    public val digestSize: DigestSize

    public fun hashFunction(): HashFunction

    public fun hash(input: BufferView): BufferView
    public fun hash(input: BufferView, output: BufferView): BufferView
}

public inline fun <R> HashPrimitive.hash(block: HashFunction.() -> R): R {
    return hashFunction().use(block)
}

public interface HashFunction : Closeable {
    public val digestSize: DigestSize

    public fun hashPart(input: BufferView)

    public fun hashFinalPart(input: BufferView): BufferView
    public fun hashFinalPart(input: BufferView, output: BufferView): BufferView
}
