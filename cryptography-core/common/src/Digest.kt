package dev.whyoleg.cryptography

import dev.whyoleg.vio.*
import kotlin.jvm.*

@JvmInline
public value class Digest(public val value: BufferView)

public interface HasherProvider {
    public fun <B : BaseHasher, P : HasherParameters> hasher(
        algorithm: HasherAlgorithm<P>,
        id: HasherId<B>,
        parameters: P
    ): B

}

public interface HasherAlgorithm<P : HasherParameters>
public interface HasherParameters

public interface HasherId<B : BaseHasher>

public object Hasher {
    public inline fun sync(): HasherId<SyncHasher> = TODO()
    public inline fun async(): HasherId<AsyncHasher> = TODO()
    public inline fun stream(): HasherId<StreamHasher> = TODO()
}

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
