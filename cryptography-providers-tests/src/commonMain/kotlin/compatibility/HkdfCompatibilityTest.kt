/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.compatibility

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.api.*
import dev.whyoleg.cryptography.providers.tests.api.compatibility.*
import dev.whyoleg.cryptography.random.*
import kotlinx.io.bytestring.*
import kotlinx.serialization.*

private const val maxInputSize = 1000
private const val maxOutputSize = 1000
private const val maxSaltSize = 10000
private const val maxInfoSize = 512

abstract class HkdfCompatibilityTest(provider: CryptographyProvider) : CompatibilityTest<HKDF>(HKDF, provider) {

    @Serializable
    private data class Parameters(
        val digestName: String,
        val salt: ByteStringAsString,
        val info: ByteStringAsString?,
        val outputSizeBytes: Int,
    ) : TestParameters {
        val digest get() = digest(digestName)
    }

    override suspend fun CompatibilityTestScope<HKDF>.generate(isStressTest: Boolean) {
        val saltIterations = when {
            isStressTest -> 10
            else         -> 5
        }
        val infoIterations = when {
            isStressTest -> 10
            else         -> 5
        }
        val outputSizeIterations = when {
            isStressTest -> 10
            else         -> 5
        }
        val deriveIterations = when {
            isStressTest -> 10
            else         -> 5
        }

        generateDigestsForCompatibility { digest, _ ->
            if (!supportsDigest(digest)) return@generateDigestsForCompatibility

            repeat(saltIterations) { _ ->
                val saltSize = CryptographyRandom.nextInt(0, maxSaltSize)
                val salt = ByteString(CryptographyRandom.nextBytes(saltSize))
                repeat(infoIterations) { ii ->
                    val info = if (ii == 0) null else ByteString(CryptographyRandom.nextBytes(maxInfoSize))
                    repeat(outputSizeIterations) { _ ->
                        val outputSize = CryptographyRandom.nextInt(1, maxOutputSize)
                        val parameters = Parameters(
                            digestName = digest.name,
                            salt = salt,
                            outputSizeBytes = outputSize,
                            info = info,
                        )
                        val parametersId = api.derivedSecrets.saveParameters(parameters)

                        val derivation = algorithm.secretDerivation(
                            digest = digest,
                            outputSize = outputSize.bytes,
                            salt = salt,
                            info = info,
                        )

                        repeat(deriveIterations) {
                            val inputSize = CryptographyRandom.nextInt(1, maxInputSize)
                            logger.log { "input.size   = $inputSize" }
                            val input = ByteString(CryptographyRandom.nextBytes(inputSize))
                            val secret = derivation.deriveSecret(input)
                            logger.log { "secret.size = ${secret.size}" }

                            assertContentEquals(secret, derivation.deriveSecret(input))

                            api.derivedSecrets.saveData(parametersId, DerivedSecretData(input, secret))
                        }
                    }
                }
            }
        }
    }

    override suspend fun CompatibilityTestScope<HKDF>.validate() {
        api.derivedSecrets.getParameters<Parameters> { parameters, parametersId, _ ->
            if (!supportsDigest(parameters.digest)) return@getParameters

            val derivation = algorithm.secretDerivation(
                digest = parameters.digest,
                outputSize = parameters.outputSizeBytes.bytes,
                salt = parameters.salt,
                info = parameters.info
            )
            api.derivedSecrets.getData<DerivedSecretData>(parametersId) { (input, secret), _, _ ->
                assertContentEquals(secret, derivation.deriveSecret(input))
            }
        }
    }
}
