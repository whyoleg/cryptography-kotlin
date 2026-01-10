package dev.whyoleg.cryptography.storage

/**
 * A resolved key handle consisting of algorithm-typed public/private objects and key [attributes].
 *
 * Providers may return lightweight wrappers that route cryptographic operations to the underlying
 * platform (e.g., Keychain). Private handles for non-extractable keys must not expose private material.
 */
@ExperimentalKeyStorageApi
public data class Handle<Public, Private>(
    val public: Public,
    val private: Private,
    val attributes: KeyAttributes,
)
