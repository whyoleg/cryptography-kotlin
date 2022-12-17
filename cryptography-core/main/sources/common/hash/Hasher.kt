package dev.whyoleg.cryptography.hash

import dev.whyoleg.cryptography.*

public interface Hasher {
    public val digestSize: Int
}

public interface SyncHasher : Hasher {
    public fun hash(dataInput: Buffer): Buffer
    public fun hash(dataInput: Buffer, digestOutput: Buffer): Buffer
}

public interface AsyncHasher : Hasher {
    public suspend fun hash(dataInput: Buffer): Buffer
    public suspend fun hash(dataInput: Buffer, digestOutput: Buffer): Buffer
}
