/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.cryptokit.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.*
import dev.whyoleg.cryptography.providers.cryptokit.internal.swiftinterop.*
import kotlinx.cinterop.*
import platform.Foundation.*

@OptIn(UnsafeNumber::class)
internal class CryptoKitDigest(
    override val id: CryptographyAlgorithmId<Digest>,
    private val doHash: (NSData) -> NSData,
    private val algorithm: SwiftHashAlgorithm,
) : Digest, Hasher {
    override fun hasher(): Hasher = this

    override fun hashBlocking(data: ByteArray): ByteArray {
        return data.useNSData(block = doHash).toByteArray()
    }

    override fun createHashFunction(): HashFunction = CryptoKitHashFunction(algorithm)
}

@OptIn(UnsafeNumber::class)
private class CryptoKitHashFunction(
    private val algorithm: SwiftHashAlgorithm,
) : HashFunction {
    private var _function: SwiftHashFunction? = null

    private val function: SwiftHashFunction
        get() = _function ?: error("Hash function is closed")

    init {
        reset()
    }

    override fun hashIntoByteArray(destination: ByteArray, destinationOffset: Int): Int {
        return function.doFinal().getIntoByteArray(destination, destinationOffset).also {
            reset()
        }
    }

    override fun hashToByteArray(): ByteArray {
        return function.doFinal().toByteArray().also {
            reset()
        }
    }

    override fun update(source: ByteArray, startIndex: Int, endIndex: Int) {
        source.useNSData(startIndex, endIndex, function::doUpdate)
    }

    override fun reset() {
        _function = SwiftHashFunction(algorithm)
    }

    override fun close() {
        _function = null
    }
}
