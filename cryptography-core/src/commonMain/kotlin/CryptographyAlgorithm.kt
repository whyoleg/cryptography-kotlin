/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography

/**
 * Marker interface for cryptographic algorithm definitions.
 *
 * Each algorithm (e.g., [AES][dev.whyoleg.cryptography.algorithms.AES],
 * [RSA][dev.whyoleg.cryptography.algorithms.RSA]) implements this interface
 * and provides access to its specific operations.
 *
 * Identified by a [CryptographyAlgorithmId] and obtained from a [CryptographyProvider].
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface CryptographyAlgorithm {
    /**
     * The typed identifier that uniquely distinguishes this algorithm
     * and is used to look it up from a [CryptographyProvider].
     */
    public val id: CryptographyAlgorithmId<*>
}

/**
 * Uniquely identifies a [CryptographyAlgorithm] and is used to look it up from a [CryptographyProvider].
 *
 * Each algorithm defines a companion object extending this class, enabling usage such as
 * `provider.get(AES.GCM)`.
 *
 * Use [CryptographyProvider.get] to look up the algorithm by its identifier.
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public abstract class CryptographyAlgorithmId<A : CryptographyAlgorithm>(public val name: String)
