package dev.whyoleg.cryptography.key

public interface KeyGenerator<K>

public interface SyncKeyGenerator<K> : KeyGenerator<K> {
    public fun generateKey(): K
}

public interface AsyncKeyGenerator<K> : KeyGenerator<K> {
    public suspend fun generateKey(): K
}
