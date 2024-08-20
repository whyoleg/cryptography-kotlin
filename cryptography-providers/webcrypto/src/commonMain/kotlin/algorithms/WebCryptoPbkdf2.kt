/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.webcrypto.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.binary.*
import dev.whyoleg.cryptography.binary.BinarySize
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.webcrypto.internal.*

internal object WebCryptoPbkdf2 : PBKDF2 {
    override fun secretDerivation(
        digest: CryptographyAlgorithmId<Digest>,
        salt: BinaryData,
        iterations: Int,
        outputSize: BinarySize,
    ): SecretDerivation = Pbkdf2SecretDerivation(
        Pbkdf2DeriveAlgorithm(digest.hashAlgorithmName(), iterations, salt.toByteArray()),
        outputSize
    )

    private class Pbkdf2SecretDerivation(
        private val algorithm: Algorithm,
        private val outputSize: BinarySize,
    ) : SecretDerivation {
        override suspend fun deriveSecret(input: BinaryData): BinaryData {
            val inputKey = WebCrypto.importKey(
                format = "raw",
                keyData = input.toByteArray(),
                algorithm = Algorithm("PBKDF2"),
                extractable = false,
                keyUsages = arrayOf("deriveBits")
            )
            return BinaryData.fromByteArray(
                WebCrypto.deriveBits(
                    algorithm = algorithm,
                    baseKey = inputKey,
                    length = outputSize.inBits
                )
            )
        }

        override fun deriveSecretBlocking(input: BinaryData): BinaryData = nonBlocking()
    }
}
