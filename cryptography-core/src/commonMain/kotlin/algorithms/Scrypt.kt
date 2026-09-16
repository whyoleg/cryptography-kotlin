/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.operations.*
import kotlinx.io.bytestring.*

/**
 * The scrypt password-based key derivation function as defined in
 * [RFC 7914](https://datatracker.ietf.org/doc/html/rfc7914).
 *
 * Scrypt derives cryptographic keys from passwords using a salt and configurable CPU and memory
 * costs. Its memory-hard design makes large-scale password guessing expensive by requiring
 * substantial memory as well as computation for each attempt.
 *
 * This API names the RFC 7914 parameters `N`, `r`, and `p` as `cost`, `blockSize`, and
 * `parallelization`, respectively. `cost` controls the main CPU and memory cost, `blockSize` controls
 * the size of the internal mixing operation, and `parallelization` controls how many independent
 * mixing operations are performed. Callers should choose values appropriate for their security
 * requirements and available resources and enforce a memory budget when processing parameters
 * supplied by an untrusted source.
 *
 * ```
 * val cost = 16_384
 * val blockSize = 8
 * val parallelization = 1
 * val maximumMemoryBytes = 128L * blockSize * (cost + 2L * parallelization + 4L)
 *
 * val derivation = provider.get(Scrypt).secretDerivation(
 *     cost = cost,
 *     blockSize = blockSize,
 *     parallelization = parallelization,
 *     outputSize = 32.bytes,
 *     salt = salt,
 *     maximumMemoryBytes = maximumMemoryBytes,
 * )
 * val derivedKey = derivation.deriveSecret(password)
 * ```
 *
 * Scrypt is intended for low-entropy inputs such as passwords. To derive keys from high-entropy
 * keying material, such as a cryptographic shared secret, use [HKDF] instead.
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface Scrypt : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<Scrypt> get() = Companion

    public companion object : CryptographyAlgorithmId<Scrypt>("SCRYPT")

    /**
     * Returns a [SecretDerivation] whose input is the password bytes and whose output has [outputSize].
     * [salt] is the per-password salt.
     *
     * The RFC 7914 cost parameter [cost] (`N`) must be greater than 1 and a power of two.
     * [blockSize] (`r`) and [parallelization] (`p`) must each be at least 1. When [blockSize] is 1,
     * [cost] must be less than 65536. To satisfy provider integer limits, [parallelization] must not
     * exceed `floor(Int.MAX_VALUE / (1024 * blockSize))`; this calculation and all memory-size
     * calculations are checked for overflow. [outputSize] must contain at least one byte.
     *
     * [maximumMemoryBytes] must be greater than zero and is a mandatory budget for the provider's
     * scrypt working buffers. It must be at least
     * `128 * blockSize * (cost + 2 * parallelization + 4)` bytes. This is not a limit or guarantee
     * for the process's resident set size (RSS), and the provider may enforce additional limits.
     */
    public fun secretDerivation(
        cost: Int,
        blockSize: Int,
        parallelization: Int,
        outputSize: BinarySize,
        salt: ByteArray,
        maximumMemoryBytes: Long,
    ): SecretDerivation

    /**
     * Returns a [SecretDerivation] whose input is the password bytes and whose output has [outputSize].
     * [salt] is the per-password salt.
     *
     * The RFC 7914 cost parameter [cost] (`N`) must be greater than 1 and a power of two.
     * [blockSize] (`r`) and [parallelization] (`p`) must each be at least 1. When [blockSize] is 1,
     * [cost] must be less than 65536. To satisfy provider integer limits, [parallelization] must not
     * exceed `floor(Int.MAX_VALUE / (1024 * blockSize))`; this calculation and all memory-size
     * calculations are checked for overflow. [outputSize] must contain at least one byte.
     *
     * [maximumMemoryBytes] must be greater than zero and is a mandatory budget for the provider's
     * scrypt working buffers. It must be at least
     * `128 * blockSize * (cost + 2 * parallelization + 4)` bytes. This is not a limit or guarantee
     * for the process's resident set size (RSS), and the provider may enforce additional limits.
     */
    public fun secretDerivation(
        cost: Int,
        blockSize: Int,
        parallelization: Int,
        outputSize: BinarySize,
        salt: ByteString,
        maximumMemoryBytes: Long,
    ): SecretDerivation = secretDerivation(
        cost = cost,
        blockSize = blockSize,
        parallelization = parallelization,
        outputSize = outputSize,
        salt = salt.asByteArray(),
        maximumMemoryBytes = maximumMemoryBytes,
    )
}
