/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.operations.*
import kotlinx.io.bytestring.*

/**
 * HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
 * as defined in [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869).
 *
 * HKDF follows a two-stage extract-then-expand paradigm:
 * the `extract` step concentrates entropy from input keying material into a pseudorandom key,
 * and the `expand` step derives an output key of the desired length from that pseudorandom key.
 *
 * ```
 * val derivation = provider.get(HKDF).secretDerivation(SHA256, outputSize = 32.bytes, salt = salt)
 * val derivedKey = derivation.deriveSecret(inputKeyingMaterial)
 * ```
 *
 * For password-based key derivation, see [PBKDF2].
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface HKDF : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<HKDF> get() = Companion

    public companion object : CryptographyAlgorithmId<HKDF>("HKDF")

    /**
     * Returns a [SecretDerivation] that derives secrets of the given [outputSize]
     * from input keying material using the [digest] hash function as the underlying PRF.
     *
     * The derivation can be strengthened with a non-secret [salt] in the `extract` step
     * and bound to a specific context with [info] in the `expand` step.
     * When [salt] is `null`, a string of zeros equal to the hash output length is used (per [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869)).
     */
    public fun secretDerivation(
        digest: CryptographyAlgorithmId<Digest>,
        outputSize: BinarySize,
        salt: ByteArray?,
        info: ByteArray? = null,
    ): SecretDerivation

    /**
     * Returns a [SecretDerivation] that derives secrets of the given [outputSize]
     * from input keying material using the [digest] hash function as the underlying PRF.
     *
     * The derivation can be strengthened with a non-secret [salt] in the `extract` step
     * and bound to a specific context with [info] in the `expand` step.
     * When [salt] is `null`, a string of zeros equal to the hash output length is used (per [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869)).
     */
    public fun secretDerivation(
        digest: CryptographyAlgorithmId<Digest>,
        outputSize: BinarySize,
        salt: ByteString?,
        info: ByteString? = null,
    ): SecretDerivation = secretDerivation(digest, outputSize, salt?.asByteArray(), info?.asByteArray())
}
