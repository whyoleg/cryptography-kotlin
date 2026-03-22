/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.operations

import dev.whyoleg.cryptography.*
import kotlinx.io.*
import kotlinx.io.bytestring.*

/**
 * Computes cryptographic hash digests.
 *
 * Use [hash] for one-shot hashing, or [createHashFunction] for incremental (streaming) hashing.
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Hasher {
    /**
     * Returns a new [HashFunction] for incremental hashing.
     *
     * The returned function accumulates data fed via [UpdateFunction.update] and produces
     * a hash when finalized. The function should be [closed][UpdateFunction.close] after use.
     */
    public fun createHashFunction(): HashFunction

    /**
     * Hashes the given [data] and returns the resulting digest as a [ByteArray].
     *
     * Use [hashBlocking] when calling from non-suspending code.
     */
    public suspend fun hash(data: ByteArray): ByteArray {
        return hashBlocking(data)
    }

    /**
     * Hashes the given [data] and returns the resulting digest as a [ByteString].
     *
     * Use [hashBlocking] when calling from non-suspending code.
     */
    public suspend fun hash(data: ByteString): ByteString {
        return hash(data.asByteArray()).asByteString()
    }

    /**
     * Hashes the given [data] read from a [RawSource] and returns the resulting digest as a [ByteString].
     *
     * Use [hashBlocking] when calling from non-suspending code.
     */
    public suspend fun hash(data: RawSource): ByteString {
        return hashBlocking(data)
    }

    /**
     * Hashes the given [data] and returns the resulting digest as a [ByteArray].
     *
     * Use [hash] when calling from suspending code.
     */
    public fun hashBlocking(data: ByteArray): ByteArray {
        return createHashFunction().use {
            it.update(data)
            it.hashToByteArray()
        }
    }

    /**
     * Hashes the given [data] and returns the resulting digest as a [ByteString].
     *
     * Use [hash] when calling from suspending code.
     */
    public fun hashBlocking(data: ByteString): ByteString {
        return hashBlocking(data.asByteArray()).asByteString()
    }

    /**
     * Hashes the given [data] read from a [RawSource] and returns the resulting digest as a [ByteString].
     *
     * Use [hash] when calling from suspending code.
     */
    public fun hashBlocking(data: RawSource): ByteString {
        return createHashFunction().use {
            it.update(data)
            it.hash()
        }
    }
}

/**
 * Incremental hash function that accumulates data and produces a digest on finalization.
 *
 * Data is fed via [update] and the digest is obtained by calling one of the finalization methods:
 * [hashIntoByteArray], [hashToByteArray], or [hash].
 * After finalization, the function can be [reset][UpdateFunction.reset] and reused,
 * or [closed][close] to release resources.
 *
 * Obtained via [Hasher.createHashFunction].
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface HashFunction : UpdateFunction {
    /**
     * Finalizes the hash computation and writes the result into [destination]
     * starting at [destinationOffset], and returns the number of bytes written.
     */
    public fun hashIntoByteArray(destination: ByteArray, destinationOffset: Int = 0): Int

    /**
     * Finalizes the hash computation and returns the result as a new [ByteArray].
     */
    public fun hashToByteArray(): ByteArray

    /**
     * Finalizes the hash computation and returns the result as a [ByteString].
     */
    public fun hash(): ByteString {
        return hashToByteArray().asByteString()
    }
}
