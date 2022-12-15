package dev.whyoleg.cryptography.api

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

public interface HashFunction : Closeable {
    public val digestSize: Int
    public fun update(dataInput: Buffer)

    public fun finish(dataInput: Buffer): Buffer
    public fun finish(dataInput: Buffer, digestOutput: Buffer): Buffer
}
