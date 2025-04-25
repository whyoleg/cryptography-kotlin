/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

public class DigestParameters(
    public val algorithm: DigestAlgorithm,
)

@Suppress("NOTHING_TO_INLINE")
public inline operator fun <I : Any> CryptographyProvider.Tag<I, DigestParameters>.invoke(
    algorithm: DigestAlgorithm,
    provider: CryptographyProvider = CryptographyProvider.Default,
): I = provider.instantiate(this, DigestParameters(algorithm))
