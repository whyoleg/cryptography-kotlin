package dev.whyoleg.cryptography.storage

/**
 * Algorithm-agnostic storage for asymmetric key pairs.
 *
 * All methods accept a binary-safe [label] which is mapped to provider-specific aliases.
 * Implementations must enforce [AccessPolicy] and non-extractable semantics.
 */
@ExperimentalKeyStorageApi
public interface AsymmetricStore<Public, Private> {
    /** Generate and persist a new key pair under [label]. Returns a handle with attributes. */
    public fun generate(label: ByteArray, access: AccessPolicy = AccessPolicy()): Handle<Public, Private>

    /** Fetch an existing key pair by [label], or null if not found. */
    public fun get(label: ByteArray): Handle<Public, Private>?

    /** Check existence by [label] without returning a handle. */
    public fun exists(label: ByteArray): Boolean

    /** Delete a key pair by [label]. Returns true if an item was removed. */
    public fun delete(label: ByteArray): Boolean
}
