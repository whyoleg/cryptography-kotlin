package dev.whyoleg.cryptography.key

import dev.whyoleg.cryptography.*

public interface KeyDecoder<K>

public interface SyncKeyDecoder<K> : KeyDecoder<K> {
    public fun decodeKey(format: String, keyDataInput: Buffer): K
}

public interface AsyncKeyDecoder<K> : KeyDecoder<K> {
    public suspend fun decodeKey(format: String, keyDataInput: Buffer): K
}
