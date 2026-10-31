/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.jdk.*
import javax.crypto.spec.*

internal class JdkPbkdf2(
    private val state: JdkCryptographyState,
) : PBKDF2 {
    override fun secretDerivation(
        digest: CryptographyAlgorithmId<Digest>,
        iterations: Int,
        outputSize: BinarySize,
        salt: ByteArray,
    ): SecretDerivation = JdkPbkdf2SecretDerivation(
        factory = resolveDigest(digest),
        salt = salt,
        iterations = iterations,
        outputSizeBits = outputSize.inBits
    )

    // resolves the digest into the `SecretKeyFactory`, fails if it's not supported
    private fun resolveDigest(digest: CryptographyAlgorithmId<Digest>): Pooled<JSecretKeyFactory> {
        val algorithm = "PBKDF2WithHmac${digest.hashAlgorithmName()}"
        return state.secretKeyFactory(algorithm)
    }
}

private class JdkPbkdf2SecretDerivation(
    private val factory: Pooled<JSecretKeyFactory>,
    private val salt: ByteArray,
    private val iterations: Int,
    private val outputSizeBits: Int,
) : SecretDerivation {
    override fun deriveSecretToByteArrayBlocking(input: ByteArray): ByteArray {
        val spec = PBEKeySpec(
            /* password = */ input.decodeToString(throwOnInvalidSequence = true).toCharArray(),
            /* salt = */ salt,
            /* iterationCount = */ iterations,
            /* keyLength = */ outputSizeBits
        )
        return factory.use { it.generateSecret(spec).encoded }
    }
}
