/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.jdk.internal.*
import java.security.*

internal object JdkScrypt : Scrypt {
    fun isSupported(provider: Provider?): Boolean = BouncyCastleBridge.supportsScrypt(provider)

    override fun secretDerivation(
        cost: Int,
        blockSize: Int,
        parallelization: Int,
        outputSize: BinarySize,
        salt: ByteArray,
        maximumMemoryBytes: Long,
    ): SecretDerivation {
        validateScryptParameters(cost, blockSize, parallelization, outputSize, maximumMemoryBytes)
        return JdkScryptSecretDerivation(cost, blockSize, parallelization, outputSize.inBytes, salt.copyOf())
    }
}

private class JdkScryptSecretDerivation(
    private val cost: Int,
    private val blockSize: Int,
    private val parallelization: Int,
    private val outputSizeBytes: Int,
    private val salt: ByteArray,
) : SecretDerivation {
    override fun deriveSecretToByteArrayBlocking(input: ByteArray): ByteArray =
        BouncyCastleBridge.generateScrypt(input, salt, cost, blockSize, parallelization, outputSizeBytes)
}

private fun validateScryptParameters(
    cost: Int,
    blockSize: Int,
    parallelization: Int,
    outputSize: BinarySize,
    maximumMemoryBytes: Long,
) {
    require(cost > 1 && (cost and (cost - 1)) == 0) { "cost must be greater than 1 and a power of two" }
    require(blockSize >= 1) { "blockSize must be at least 1" }
    require(parallelization >= 1) { "parallelization must be at least 1" }
    require(outputSize.inBytes >= 1) { "outputSize must be at least 1 byte" }
    require(maximumMemoryBytes > 0) { "maximumMemoryBytes must be greater than 0" }
    require(blockSize != 1 || cost < 65536) { "cost must be less than 65536 when blockSize is 1" }

    val blockSizeBytesWithBits = checkedMultiply(1024L, blockSize.toLong(), "blockSize")
    val maximumParallelization = Int.MAX_VALUE.toLong() / blockSizeBytesWithBits
    require(parallelization.toLong() <= maximumParallelization) {
        "parallelization is too large for blockSize"
    }

    val costAndOverhead = checkedAdd(
        checkedAdd(cost.toLong(), checkedMultiply(2L, parallelization.toLong(), "parallelization"), "scrypt memory"),
        4L,
        "scrypt memory",
    )
    val minimumMemoryBytes = checkedMultiply(
        checkedMultiply(128L, blockSize.toLong(), "blockSize"),
        costAndOverhead,
        "scrypt memory",
    )
    require(minimumMemoryBytes <= maximumMemoryBytes) {
        "maximumMemoryBytes must be at least $minimumMemoryBytes for these scrypt parameters"
    }
}

private fun checkedAdd(left: Long, right: Long, parameter: String): Long {
    require(left <= Long.MAX_VALUE - right) { "$parameter is too large" }
    return left + right
}

private fun checkedMultiply(left: Long, right: Long, parameter: String): Long {
    require(left == 0L || right <= Long.MAX_VALUE / left) { "$parameter is too large" }
    return left * right
}
