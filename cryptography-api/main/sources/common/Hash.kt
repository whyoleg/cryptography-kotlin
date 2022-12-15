package dev.whyoleg.cryptography.api

public interface Hasher {
    public val digestSize: Int
    public fun hash(dataInput: Buffer): Buffer
    public fun hash(dataInput: Buffer, digestOutput: Buffer): Buffer
}

public interface AsyncHasher {
    public val digestSize: Int
    public suspend fun hash(dataInput: Buffer): Buffer
    public suspend fun hash(dataInput: Buffer, digestOutput: Buffer): Buffer
}

public interface HashFunction : Closeable {
    public val digestSize: Int
    public fun update(dataInput: Buffer)

    //TODO: finish(input, output) - ?
    public fun finish(): Buffer
    public fun finish(digestOutput: Buffer): Buffer
}
