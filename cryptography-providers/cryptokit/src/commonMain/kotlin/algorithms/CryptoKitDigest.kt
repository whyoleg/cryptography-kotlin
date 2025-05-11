/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.cryptokit.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import platform.Foundation.*

internal class CryptoKitDigest(
    override val id: CryptographyAlgorithmId<Digest>,
    private val doHash: (NSData) -> NSData,
) : Digest, Hasher {
    override fun hasher(): Hasher = this

    override fun hashBlocking(data: ByteArray): ByteArray {
        return data.useNSData(doHash).toByteArray()
    }

    override fun createHashFunction(): HashFunction {
        TODO("Not yet implemented")
    }
}
