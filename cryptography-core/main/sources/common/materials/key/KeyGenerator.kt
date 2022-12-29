package dev.whyoleg.cryptography.materials.key

public interface KeyGenerator<K : Key> {
    public suspend fun generateKey(): K
    public fun generateKeyBlocking(): K
}
