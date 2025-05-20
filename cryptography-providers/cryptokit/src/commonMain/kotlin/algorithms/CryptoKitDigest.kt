/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.cryptokit.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.swiftinterop.*
import dev.whyoleg.cryptography.providers.cryptokit.operations.*
import kotlinx.cinterop.*
import platform.Foundation.*

@OptIn(UnsafeNumber::class)
internal class CryptoKitDigest(
    override val id: CryptographyAlgorithmId<Digest>,
    private val algorithm: SwiftHashAlgorithm,
) : Digest, Hasher {
    override fun hasher(): Hasher = this
    override fun createHashFunction(): HashFunction = CryptoKitHashFunction(algorithm)
}

@OptIn(UnsafeNumber::class)
private class CryptoKitHashFunction(
    algorithm: SwiftHashAlgorithm,
) : HashBasedFunction(algorithm), HashFunction {
    private fun hashToNSData(): NSData = function.doFinal().also { reset() }
    override fun hashIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
        return hashToNSData().getIntoByteArray(destination, destinationOffset)
    }

    override fun hashToByteArray(): ByteArray {
        return hashToNSData().toByteArray()
    }
}
