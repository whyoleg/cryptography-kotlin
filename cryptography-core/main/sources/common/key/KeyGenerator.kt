package dev.whyoleg.cryptography.key

public interface KeyGenerator<K, KP> {
    public val defaultParameters: KP

    public interface Provider {
        public fun <K, KP> syncKeyGenerator(algorithm: KeyAlgorithm<K, KP>): SyncKeyGenerator<K, KP>
        public fun <K, KP> asyncKeyGenerator(algorithm: KeyAlgorithm<K, KP>): AsyncKeyGenerator<K, KP>
    }
}

public interface SyncKeyGenerator<K, KP> : KeyGenerator<K, KP> {
    public fun generateKey(parameters: KP = defaultParameters): K
}

public interface AsyncKeyGenerator<K, KP> : KeyGenerator<K, KP> {
    public suspend fun generateKey(parameters: KP = defaultParameters): K
}
