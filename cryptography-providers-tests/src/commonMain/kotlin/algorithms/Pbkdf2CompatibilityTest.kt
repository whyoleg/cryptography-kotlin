/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

@file:Suppress("ArrayInDataClass")

package dev.whyoleg.cryptography.providers.tests.algorithms

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.binary.*
import dev.whyoleg.cryptography.binary.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.providers.tests.api.*
import dev.whyoleg.cryptography.providers.tests.api.compatibility.*
import dev.whyoleg.cryptography.random.*
import kotlinx.serialization.*
import kotlin.test.*

// TODO: handle zero length
// TODO: define input/output sizes
private const val maxInputSize = 100
private const val maxOutputSize = 256
private const val maxSaltSize = 10000
private const val minIterations = 200000 // TODO
private const val maxIterations = 2000000 // TODO

abstract class Pbkdf2CompatibilityTest(provider: CryptographyProvider) : CompatibilityTest<PBKDF2>(PBKDF2, provider) {

    @Serializable
    private data class Parameters(
        val digestName: String,
        val salt: Base64ByteArray,
        val iterations: Int,
        val outputSizeBytes: Int,
    ) : TestParameters {
        val digest get() = digest(digestName)
    }

    override suspend fun CompatibilityTestScope<PBKDF2>.generate(isStressTest: Boolean) {
        val saltIterations = when {
            isStressTest -> 10
            else -> 1
        }
        val iterationIterations = when {
            isStressTest -> 10
            else         -> 2
        }
        val outputSizeIterations = when {
            isStressTest -> 10
            else         -> 2
        }
        val deriveIterations = when {
            isStressTest -> 10
            else         -> 2
        }

        listOf(SHA256, SHA512).forEach { digest ->
            if (!supportsDigest(digest)) return@forEach

            repeat(saltIterations) { _ ->
                val saltSize = CryptographyRandom.nextInt(1, maxSaltSize)
                val salt = CryptographyRandom.nextBytes(saltSize)
                repeat(iterationIterations) { _ ->
                    val iterations = CryptographyRandom.nextInt(minIterations, maxIterations)
                    repeat(outputSizeIterations) { _ ->
                        val outputSize = CryptographyRandom.nextInt(1, maxOutputSize)
                        val parameters = Parameters(
                            digestName = digest.name,
                            salt = salt,
                            iterations = iterations,
                            outputSizeBytes = outputSize,
                        )
                        val parametersId = api.derivedSecrets.saveParameters(parameters)

                        val derivation = algorithm.secretDerivation(
                            digest = digest,
                            salt = BinaryData.fromByteArray(salt),
                            iterations = iterations,
                            outputSize = outputSize.bytes
                        )

                        repeat(deriveIterations) {
                            println("${digest.name}/${saltSize}/$iterations/$outputSize/$it")
                            val inputSize = CryptographyRandom.nextInt(1, maxInputSize)
                            logger.log { "input.size   = $inputSize" }
                            val input: BinaryData = BinaryData.fromUtf8String(generateRandomString(inputSize))
                            val secret = derivation.deriveSecret(input)
                            logger.log { "secret.size = ${secret.size}" }

                            api.derivedSecrets.saveData(parametersId, DerivedSecretData(input.toByteArray(), secret.toByteArray()))
                        }
                    }
                }
            }
        }
    }

    override suspend fun CompatibilityTestScope<PBKDF2>.validate() {
        api.derivedSecrets.getParameters<Parameters> { parameters, parametersId, _ ->
            if (!supportsDigest(parameters.digest)) return@getParameters

            val derivation = algorithm.secretDerivation(
                digest = parameters.digest,
                salt = BinaryData.fromByteArray(parameters.salt),
                iterations = parameters.iterations,
                outputSize = parameters.outputSizeBytes.bytes
            )
            api.derivedSecrets.getData<DerivedSecretData>(parametersId) { (input, secret), reference, _ ->
                println("validate: $reference")
                assertContentEquals(secret, derivation.deriveSecret(BinaryData.fromByteArray(input)).toByteArray())
            }
        }
    }
}

private const val charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_=-!@#$%^&*()"
private fun generateRandomString(length: Int): String {
    return CharArray(length) { charset.random() }.concatToString()
}
