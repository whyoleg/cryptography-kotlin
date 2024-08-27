/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.binary.*
import dev.whyoleg.cryptography.binary.BinarySize
import dev.whyoleg.cryptography.operations.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface PBKDF2 : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<PBKDF2> get() = Companion

    public companion object : CryptographyAlgorithmId<PBKDF2>("PBKDF2")

    public fun secretDerivation(
        digest: CryptographyAlgorithmId<Digest>,
        salt: BinaryData,
        iterations: Int,
        outputSize: BinarySize,
    ): SecretDerivation
}
