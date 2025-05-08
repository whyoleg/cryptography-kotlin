/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import kotlinx.io.bytestring.*

public class HkdfParameters(
    public val digest: DigestAlgorithm,
    public val salt: ByteString,
    public val info: ByteString? = null,
)

@Suppress("NOTHING_TO_INLINE")
public inline operator fun <I : Any> CryptographyProvider.Tag<I, HkdfParameters>.invoke(
    digest: DigestAlgorithm,
    provider: CryptographyProvider = CryptographyProvider.Default,
): I = provider.instantiate(this, HkdfParameters(digest))
