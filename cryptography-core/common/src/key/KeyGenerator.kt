package dev.whyoleg.cryptography.key

import dev.whyoleg.cryptography.*

public interface KeyGenerator<K : CryptographyKey> : CryptographyPrimitive {
    public interface Sync<K : CryptographyKey> : KeyGenerator<K> {
        public fun generateKey(): K
    }

    public interface Async<K : CryptographyKey> : KeyGenerator<K> {
        public suspend fun generateKey(): K
    }
}
