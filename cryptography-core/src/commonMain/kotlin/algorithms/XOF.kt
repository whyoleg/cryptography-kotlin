/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

@file:OptIn(CryptographyProviderApi::class)

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.operations.*

/**
 * Extendable-output function (XOF).
 *
 * A hasher is configured with a positive output size before any input is supplied. Finalizing a
 * hash produces exactly that many bytes and resets the hash function for reuse; this API does not
 * expose incremental squeezing.
 */
@SubclassOptInRequired(CryptographyProviderApi::class)
public interface XOF : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<XOF>

    /** Returns a hasher which produces exactly [outputSize] bytes. */
    public fun hasher(outputSize: BinarySize): Hasher
}

/** SHAKE256 extendable-output function defined in FIPS 202. */
public object SHAKE256 : CryptographyAlgorithmId<XOF>("SHAKE256")
