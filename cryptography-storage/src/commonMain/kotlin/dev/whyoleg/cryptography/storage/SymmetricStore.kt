package dev.whyoleg.cryptography.storage

/**
 * Algorithm-agnostic storage for symmetric keys.
 *
 * Symmetric stores return handles with a [public][Handle.public] value equal to the algorithm key
 * and a [private][Handle.private] placeholder (typically [Unit]).
 */
@ExperimentalKeyStorageApi
public interface SymmetricStore<Key> {
    /** Generate and persist a new key under [label]. Returns a handle with attributes. */
    public fun generate(label: ByteArray, access: AccessPolicy = AccessPolicy()): Handle<Key, Unit>

    /** Fetch an existing key by [label], or null if not found. */
    public fun get(label: ByteArray): Handle<Key, Unit>?

    /** Check existence by [label] without returning a handle. */
    public fun exists(label: ByteArray): Boolean

    /** Delete a key by [label]. Returns true if an item was removed. */
    public fun delete(label: ByteArray): Boolean
}
