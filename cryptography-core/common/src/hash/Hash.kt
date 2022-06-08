package dev.whyoleg.cryptography.hash

import dev.whyoleg.vio.*

public interface HashParameters {
    public val digestSize: DigestSize
}

//TODO: better name?
public interface Hash {
    public val digestSize: DigestSize

    public fun hashFunction(): HashFunction

    public fun hash(input: BufferView): BufferView
    public fun hash(input: BufferView, output: BufferView): BufferView
}

public inline fun <R> Hash.hash(block: HashFunction.() -> R): R {
    return hashFunction().use(block)
}
