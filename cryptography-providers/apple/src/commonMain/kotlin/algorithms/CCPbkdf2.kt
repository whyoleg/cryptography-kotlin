/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.binary.*
import dev.whyoleg.cryptography.binary.BinarySize
import dev.whyoleg.cryptography.operations.*
import dev.whyoleg.cryptography.providers.apple.internal.*
import kotlinx.cinterop.*
import platform.CoreCrypto.*

internal object CCPbkdf2 : PBKDF2 {
    override fun secretDerivation(
        digest: CryptographyAlgorithmId<Digest>,
        salt: BinaryData,
        iterations: Int,
        outputSize: BinarySize,
    ): SecretDerivation = Pbkdf2SecretDerivation(digest.pbkdh2Algorithm(), salt.toByteArray(), iterations, outputSize)
}

// TODO: handle zeros
private class Pbkdf2SecretDerivation(
    private val algorithm: CCPseudoRandomAlgorithm,
    private val salt: ByteArray,
    private val iterations: Int,
    private val outputSize: BinarySize,
) : SecretDerivation {
    @OptIn(UnsafeNumber::class)
    override fun deriveSecretBlocking(input: BinaryData): BinaryData {
        val output = ByteArray(outputSize.inBytes)
        val result = CCKeyDerivationPBKDF(
            algorithm = kCCPBKDF2,
            password = input.toUtf8String(throwOnInvalidSequence = true),
            passwordLen = input.size.inBytes.convert(),
            salt = salt.asUByteArray().refTo(0),
            saltLen = salt.size.convert(),
            prf = algorithm,
            rounds = iterations.convert(),
            derivedKey = output.asUByteArray().refTo(0),
            derivedKeyLen = output.size.convert()
        )
        when (result) {
            kCCSuccess    -> return BinaryData.fromByteArray(output)
            kCCParamError -> error("Illegal parameter value.")
            else          -> error("CCKeyDerivationPBKDF failed with code $result")
        }
    }

    override suspend fun deriveSecret(input: BinaryData): BinaryData = deriveSecretBlocking(input)
}