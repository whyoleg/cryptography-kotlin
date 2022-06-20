package dev.whyoleg.cryptography.digest

import dev.whyoleg.cryptography.*
import dev.whyoleg.vio.*
import kotlin.jvm.*

@JvmInline
public value class Digest(public val value: BufferView)

public interface BaseHasher : CryptographyPrimitive

public interface Hasher : BaseHasher {
    public companion object : CryptographyPrimitiveId<Hasher>

    public val digestSize: BinarySize

    public fun hash(input: BufferView): Digest
    public fun hash(input: BufferView, digestOutput: Digest): Digest
}

public interface AsyncHasher : BaseHasher {
    public companion object : CryptographyPrimitiveId<AsyncHasher>

    public val digestSize: BinarySize

    public suspend fun hashAsync(input: BufferView): Digest
    public suspend fun hashAsync(input: BufferView, digestOutput: Digest): Digest
}

public interface StreamHasher : BaseHasher {
    public companion object : CryptographyPrimitiveId<StreamHasher>

    public fun createHashFunction(): HashFunction
}

public interface HashFunction : Closeable {
    public val digestSize: BinarySize

    public fun hashPart(input: BufferView)

    public fun hashFinalPart(input: BufferView): BufferView
    public fun hashFinalPart(input: BufferView, digestOutput: BufferView): BufferView
}
