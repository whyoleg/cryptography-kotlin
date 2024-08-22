/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.binary.*
import dev.whyoleg.cryptography.binary.BinarySize
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import javax.crypto.spec.*

internal class JdkPbkdf2(
    private val state: JdkCryptographyState,
) : PBKDF2 {
    override fun secretDerivation(
        digest: CryptographyAlgorithmId<Digest>,
        salt: BinaryData,
        iterations: Int,
        outputSize: BinarySize,
    ): SecretDerivation = JdkPbkdf2SecretDerivation(
        state = state,
        algorithm = "PBKDF2WithHmac${digest.hashAlgorithmName()}",
        salt = salt.toByteArray(),
        iterations = iterations,
        outputSizeBits = outputSize.inBits
    )
}

private class JdkPbkdf2SecretDerivation(
    state: JdkCryptographyState,
    algorithm: String,
    private val salt: ByteArray,
    private val iterations: Int,
    private val outputSizeBits: Int,
) : SecretDerivation {
    private val factory = state.secretKeyFactory(algorithm)

    override fun deriveSecretBlocking(input: BinaryData): BinaryData {
        val spec = PBEKeySpec(
            /* password = */ input.toUtf8String(throwOnInvalidSequence = true).toCharArray(),
            /* salt = */ salt,
            /* iterationCount = */ iterations,
            /* keyLength = */ outputSizeBits
        )
        val key = factory.use { it.generateSecret(spec) }
        return BinaryData.fromByteArray(key.encoded)
    }

    override suspend fun deriveSecret(input: BinaryData): BinaryData = deriveSecretBlocking(input)
}
