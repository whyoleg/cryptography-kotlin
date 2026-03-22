/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.operations.*
import kotlinx.io.bytestring.*

/**
 * Password-Based Key Derivation Function 2 (PBKDF2)
 * as defined in [RFC 8018](https://datatracker.ietf.org/doc/html/rfc8018).
 *
 * PBKDF2 derives cryptographic keys from passwords by repeatedly applying a pseudorandom function.
 * The iteration count controls the computational cost, making brute-force attacks more expensive.
 * A random salt prevents precomputed rainbow table attacks.
 *
 * ```
 * val derivation = provider.get(PBKDF2).secretDerivation(SHA256, iterations = 210_000, outputSize = 32.bytes, salt = salt)
 * val derivedKey = derivation.deriveSecret(password)
 * ```
 *
 * For deriving keys from already-strong keying material, see [HKDF].
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface PBKDF2 : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<PBKDF2> get() = Companion

    public companion object : CryptographyAlgorithmId<PBKDF2>("PBKDF2")

    /**
     * Returns a [SecretDerivation] that derives secrets of the given [outputSize] from a password
     * using the [digest] hash function over [iterations] HMAC rounds.
     *
     * The [salt] prevents rainbow table attacks. Higher [iterations] values increase resistance to brute-force attacks at the cost of derivation time.
     */
    public fun secretDerivation(
        digest: CryptographyAlgorithmId<Digest>,
        iterations: Int,
        outputSize: BinarySize,
        salt: ByteArray,
    ): SecretDerivation

    /**
     * Returns a [SecretDerivation] that derives secrets of the given [outputSize] from a password
     * using the [digest] hash function over [iterations] HMAC rounds.
     *
     * The [salt] prevents rainbow table attacks. Higher [iterations] values increase resistance to brute-force attacks at the cost of derivation time.
     */
    public fun secretDerivation(
        digest: CryptographyAlgorithmId<Digest>,
        iterations: Int,
        outputSize: BinarySize,
        salt: ByteString,
    ): SecretDerivation = secretDerivation(digest, iterations, outputSize, salt.asByteArray())
}
