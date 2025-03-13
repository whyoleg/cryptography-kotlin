/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

public class ShakeParameters(
    public val algorithm: ShakeAlgorithm,
)

public class ShakeHashParameters(
    public val outputSize: BinarySize,
)

public enum class ShakeAlgorithm { B128, B256 }

@Suppress("NOTHING_TO_INLINE")
public inline operator fun <I : Any> CryptographyProvider.Tag<I, ShakeParameters>.invoke(
    algorithm: ShakeAlgorithm,
    provider: CryptographyProvider = CryptographyProvider.Default,
): I = provider.instantiate(this, ShakeParameters(algorithm))
