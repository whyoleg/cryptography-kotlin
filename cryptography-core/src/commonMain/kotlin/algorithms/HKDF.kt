/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.operations.*
import kotlinx.io.bytestring.*

@SubclassOptInRequired(CryptographyProviderApi::class)
public interface HKDF : CryptographyAlgorithm {
    override val id: CryptographyAlgorithmId<HKDF> get() = Companion

    public companion object : CryptographyAlgorithmId<HKDF>("HKDF")

    public fun secretDerivation(
        digest: CryptographyAlgorithmId<Digest>,
        outputSize: BinarySize,
        salt: ByteArray?,
        info: ByteArray? = null,
    ): SecretDerivation

    public fun secretDerivation(
        digest: CryptographyAlgorithmId<Digest>,
        outputSize: BinarySize,
        salt: ByteString?,
        info: ByteString? = null,
    ): SecretDerivation = secretDerivation(digest, outputSize, salt?.asByteArray(), info?.asByteArray())
}
