package dev.whyoleg.cryptography.hash

import dev.whyoleg.cryptography.*
import dev.whyoleg.vio.*

public interface HashPrimitive : CryptographyPrimitive {
    public val digestSize: BinarySize

    public fun hash(input: BufferView): Digest
    public fun hash(input: BufferView, output: BufferView): Digest

    public suspend fun hashSuspend(input: BufferView): Digest
    public suspend fun hashSuspend(input: BufferView, output: BufferView): Digest

    public fun hashFunction(): HashFunction
}

public inline fun <R> HashPrimitive.hash(block: HashFunction.() -> R): R {
    return hashFunction().use(block)
}
