package dev.whyoleg.cryptography.hash

import dev.whyoleg.vio.*

public interface HashOperation {
    public val digestSize: DigestSize

    public fun createFunction(): HashFunction

    public operator fun invoke(input: BufferView): BufferView
    public operator fun invoke(input: BufferView, output: BufferView): BufferView
}

public inline operator fun <R> HashOperation.invoke(block: HashFunction.() -> R): R {
    return createFunction().use(block)
}
