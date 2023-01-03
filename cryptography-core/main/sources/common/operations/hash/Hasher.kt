package dev.whyoleg.cryptography.operations.hash

import dev.whyoleg.cryptography.io.*

public interface Hasher {
    public val digestSize: Int
    public suspend fun hash(dataInput: Buffer): Buffer
    public fun hashBlocking(dataInput: Buffer): Buffer
}
