package dev.whyoleg.cryptography.hash

import dev.whyoleg.cryptography.*

public interface Hasher {
    public val digestSize: Int

    public interface Provider {
        public fun syncHasher(algorithm: HashAlgorithm): SyncHasher
        public fun asyncHasher(algorithm: HashAlgorithm): AsyncHasher
        public fun hashFunction(algorithm: HashAlgorithm): HashFunction
    }
}

public interface SyncHasher : Hasher {
    public fun hash(dataInput: Buffer): Buffer
    public fun hash(dataInput: Buffer, digestOutput: Buffer): Buffer
}

public interface AsyncHasher : Hasher {
    public suspend fun hash(dataInput: Buffer): Buffer
    public suspend fun hash(dataInput: Buffer, digestOutput: Buffer): Buffer
}
