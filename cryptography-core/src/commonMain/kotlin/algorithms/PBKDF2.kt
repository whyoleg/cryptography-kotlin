/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.operations.*
import kotlinx.io.bytestring.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface PBKDF2 : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<PBKDF2> get() = Companion

    public companion object : CryptographyAlgorithmId<PBKDF2>("PBKDF2")

    public fun secretDerivation(
        digest: CryptographyAlgorithmId<Digest>,
        iterations: Int,
        outputSize: BinarySize,
        salt: ByteArray,
    ): SecretDerivation

    public fun secretDerivation(
        digest: CryptographyAlgorithmId<Digest>,
        iterations: Int,
        outputSize: BinarySize,
        salt: ByteString,
    ): SecretDerivation = secretDerivation(digest, iterations, outputSize, salt.asByteArray())
}
