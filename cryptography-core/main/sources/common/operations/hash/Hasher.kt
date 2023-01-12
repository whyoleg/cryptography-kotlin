package dev.whyoleg.cryptography.operations.hash

import dev.whyoleg.cryptography.io.*

public interface Hasher {
    public suspend fun hash(dataInput: Buffer): Buffer
    public fun hashBlocking(dataInput: Buffer): Buffer
}
