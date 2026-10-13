/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.base.algorithms.*
import dev.whyoleg.cryptography.providers.jdk.internal.*
import java.security.*

internal object JdkScrypt : Scrypt {
    fun isSupported(provider: Provider?): Boolean = BouncyCastleBridge.supportsScrypt(provider)

    override fun secretDerivation(
        cost: Int,
        blockSize: Int,
        parallelization: Int,
        maximumMemoryBytes: Long,
        outputSize: BinarySize,
        salt: ByteArray,
    ): SecretDerivation {
        validateScryptParameters(cost, blockSize, parallelization, maximumMemoryBytes, outputSize)
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
