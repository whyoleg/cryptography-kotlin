package dev.whyoleg.cryptography.key

import dev.whyoleg.cryptography.*

public interface KeyGenerator<K>

public interface SyncKeyGenerator<K> : KeyGenerator<K> {
    public fun generateKey(): K
}

public interface AsyncKeyGenerator<K> : KeyGenerator<K> {
    public suspend fun generateKey(): K
}


public interface SyncKeyDecoder<K> {
    public fun decodeKey(format: String, keyDataInput: Buffer): K
}

public interface SyncKeyEncoder {
    public fun encodeKey(format: String): Buffer
    public fun encodeKey(format: String, keyDataOutput: Buffer): Buffer
}
