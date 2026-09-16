/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.compatibility

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import dev.whyoleg.cryptography.providers.tests.compatibility.api.*
import dev.whyoleg.cryptography.random.*
import kotlinx.io.bytestring.*
import kotlinx.serialization.*

abstract class ScryptCompatibilityTest(provider: CryptographyProvider) : CompatibilityTest<Scrypt>(Scrypt, provider) {

    @Serializable
    private data class Parameters(
        val salt: SerializableByteString,
        val cost: Int,
        val blockSize: Int,
        val parallelization: Int,
        val outputSizeBytes: Int,
        val maximumMemoryBytes: Long,
    ) : TestParameters

    override suspend fun CompatibilityTestScope<Scrypt>.generate(isStressTest: Boolean) {
        val parameterSets = if (isStressTest) 4 else 1
        val derivations = if (isStressTest) 4 else 2

        repeat(parameterSets) {
            val cost = if (isStressTest) 1024 else 16
            val blockSize = 8
            val parallelization = 1
            val parameters = Parameters(
                salt = ByteString(CryptographyRandom.nextBytes(16)),
                cost = cost,
                blockSize = blockSize,
                parallelization = parallelization,
                outputSizeBytes = 64,
                maximumMemoryBytes = 128L * blockSize * (cost + 2L * parallelization + 4L),
            )
            val parametersId = api.derivedSecrets.saveParameters(parameters)
            val derivation = algorithm.secretDerivation(
                cost = parameters.cost,
                blockSize = parameters.blockSize,
                parallelization = parameters.parallelization,
                outputSize = parameters.outputSizeBytes.bytes,
                salt = parameters.salt,
                maximumMemoryBytes = parameters.maximumMemoryBytes,
            )

            repeat(derivations) {
                val input = ByteString(CryptographyRandom.nextBytes(32))
                val secret = derivation.deriveSecret(input)
                assertContentEquals(secret, derivation.deriveSecret(input))
                api.derivedSecrets.saveData(parametersId, DerivedSecretData(input, secret))
            }
        }
    }

    override suspend fun CompatibilityTestScope<Scrypt>.validate() {
        api.derivedSecrets.getParameters<Parameters> { parameters, parametersId, _ ->
            val derivation = algorithm.secretDerivation(
                cost = parameters.cost,
                blockSize = parameters.blockSize,
                parallelization = parameters.parallelization,
                outputSize = parameters.outputSizeBytes.bytes,
                salt = parameters.salt,
                maximumMemoryBytes = parameters.maximumMemoryBytes,
            )
            api.derivedSecrets.getData<DerivedSecretData>(parametersId) { (input, secret), _, _ ->
                assertContentEquals(secret, derivation.deriveSecret(input))
            }
        }
    }
}
