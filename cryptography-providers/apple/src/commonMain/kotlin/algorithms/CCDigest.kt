/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.apple.internal.*
import kotlinx.cinterop.*

internal class CCDigest(
    private val hashAlgorithm: CCHashAlgorithm,
    override val id: CryptographyAlgorithmId<Digest>,
) : Hasher, Digest {
    override fun hasher(): Hasher = this

    @OptIn(ExperimentalUnsignedTypes::class)
    override fun hashBlocking(data: ByteArray): ByteArray {
        val output = ByteArray(hashAlgorithm.digestSize)
        hashAlgorithm.ccHash(
            data = data.fixEmpty().refTo(0),
            dataLength = data.size.convert(),
            digest = output.asUByteArray().refTo(0)
        )
        return output
    }
}
