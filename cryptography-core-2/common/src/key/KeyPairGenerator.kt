package dev.whyoleg.cryptography.key

import dev.whyoleg.cryptography.*

public interface KeyPairGenerator<K : CryptographyKey.Pair> : CryptographyPrimitive {
    public interface Sync<K : CryptographyKey.Pair> : KeyPairGenerator<K> {
        public fun generateKeyPair(): K
    }

    public interface Async<K : CryptographyKey.Pair> : KeyPairGenerator<K> {
        public suspend fun generateKeyPair(): K
    }
}
