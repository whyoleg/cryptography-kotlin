/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.apple.*

import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.operations.hash.*
import kotlinx.cinterop.*
import platform.CoreCrypto.*
import platform.Security.*

internal class CCDigest(
    private val hashAlgorithm: CCHashAlgorithm,
    override val id: CryptographyAlgorithmId<Digest>,
) : Hasher, Digest {
    override fun hasher(): Hasher = this

    @OptIn(ExperimentalUnsignedTypes::class)
    override fun hashBlocking(dataInput: ByteArray): ByteArray {
        val output = ByteArray(hashAlgorithm.digestSize)
        hashAlgorithm.ccHash(
            data = dataInput.fixEmpty().refTo(0),
            dataLength = dataInput.size.convert(),
            digest = output.asUByteArray().refTo(0)
        )
        return output
    }
}
