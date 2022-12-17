package dev.whyoleg.cryptography.key

import dev.whyoleg.cryptography.*

public interface KeyEncoder

public interface SyncKeyEncoder {
    public fun encodeKey(format: String): Buffer
    public fun encodeKey(format: String, keyDataOutput: Buffer): Buffer
}

public interface AsyncKeyEncoder {
    public suspend fun encodeKey(format: String): Buffer
    public suspend fun encodeKey(format: String, keyDataOutput: Buffer): Buffer
}
