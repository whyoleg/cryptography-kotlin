package dev.whyoleg.cryptography

import dev.whyoleg.vio.*
import kotlin.jvm.*

@JvmInline
public value class Digest(public val value: BufferView)

//TODO: naming
public interface BaseHasher

public interface SyncHasher : BaseHasher {
    public val digestSize: BinarySize

    public fun hash(input: BufferView): Digest
    public fun hash(input: BufferView, digestOutput: Digest): Digest
}

public interface AsyncHasher : BaseHasher {
    public val digestSize: BinarySize

    public suspend fun hashAsync(input: BufferView): Digest
    public suspend fun hashAsync(input: BufferView, digestOutput: Digest): Digest
}

public interface StreamHasher : BaseHasher {
    public fun createHashFunction(): HashFunction
}

public interface HashFunction : Closeable {
    public val digestSize: BinarySize

    public fun hashPart(input: BufferView)

    public fun hashFinalPart(input: BufferView): Digest
    public fun hashFinalPart(input: BufferView, digestOutput: Digest): Digest
}
