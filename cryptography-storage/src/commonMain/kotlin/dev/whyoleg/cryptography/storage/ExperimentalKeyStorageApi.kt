package dev.whyoleg.cryptography.storage

/**
 * Marks storage-related APIs as experimental.
 *
 * Storage APIs are new and may evolve. Consumers should explicitly opt in and
 * be prepared for source changes until the API is stabilized.
 */
@RequiresOptIn(level = RequiresOptIn.Level.WARNING)
public annotation class ExperimentalKeyStorageApi
