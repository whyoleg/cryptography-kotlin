/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.algorithms.asymmetric

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.api.*
import dev.whyoleg.cryptography.providers.tests.api.compatibility.*
import dev.whyoleg.cryptography.random.*
import kotlinx.io.bytestring.*
import kotlinx.serialization.*
import kotlin.test.*

private const val maxDataSize = 10000

abstract class EcdsaCompatibilityTest(
    provider: CryptographyProvider,
) : EcCompatibilityTest<ECDSA.PublicKey, ECDSA.PrivateKey, ECDSA.KeyPair, ECDSA>(ECDSA, provider) {
    @Serializable
    private data class SignatureParameters(
        val digestName: String,
        val signatureFormat: ECDSA.SignatureFormat,
    ) : TestParameters {
        val digest get() = digest(digestName)
    }

    override suspend fun CompatibilityTestScope<ECDSA>.generate(isStressTest: Boolean) {
        val signatureIterations = when {
            isStressTest -> 5
            else         -> 2
        }

        val signatureParametersList = buildList {
            listOf(ECDSA.SignatureFormat.RAW, ECDSA.SignatureFormat.DER).forEach { signatureFormat ->
                generateDigestsForCompatibility { digest, _ ->
                    if (!supportsDigest(digest)) return@generateDigestsForCompatibility

                    val parameters = SignatureParameters(digest.name, signatureFormat)
                    val id = api.signatures.saveParameters(parameters)
                    add(id to parameters)
                }
            }
        }
        generateCurves { curve ->
            if (!supportsCurve(curve)) return@generateCurves

            val keyParametersId = api.keyPairs.saveParameters(KeyParameters(curve.name))
            generateKeys(
                curve = curve,
                keyParametersId = keyParametersId,
                isStressTest = isStressTest
            ) { keyPair, keyReference, keyParameters ->
                signatureParametersList.forEach { (signatureParametersId, signatureParameters) ->
                    logger.log { "digest = ${signatureParameters.digestName}, signatureFormat = ${signatureParameters.signatureFormat}" }
                    val signer =
                        keyPair.privateKey.signatureGenerator(signatureParameters.digest, signatureParameters.signatureFormat)
                    val verifier =
                        keyPair.publicKey.signatureVerifier(signatureParameters.digest, signatureParameters.signatureFormat)

                    repeat(signatureIterations) {
                        val dataSize = CryptographyRandom.nextInt(maxDataSize)
                        logger.log { "data.size      = $dataSize" }
                        val data = ByteString(CryptographyRandom.nextBytes(dataSize))
                        val signature = signer.generateSignature(data)
                        logger.log { "signature.size = ${signature.size}" }

                        assertTrue(verifier.verifySignature(data, signature), "Initial Verify")

                        api.signatures.saveData(signatureParametersId, SignatureData(keyReference, data, signature))
                    }
                }
            }
        }
    }

    override suspend fun CompatibilityTestScope<ECDSA>.validate() {
        val keyPairs = validateKeys()

        api.signatures.getParameters<SignatureParameters> { signatureParameters, parametersId, _ ->
            if (!supportsDigest(signatureParameters.digest)) return@getParameters

            api.signatures.getData<SignatureData>(parametersId) { (keyReference, data, signature), _, _ ->
                val (publicKeys, privateKeys) = keyPairs[keyReference] ?: return@getData
                val verifiers = publicKeys.map { it.signatureVerifier(signatureParameters.digest, signatureParameters.signatureFormat) }
                val generators = privateKeys.map { it.signatureGenerator(signatureParameters.digest, signatureParameters.signatureFormat) }

                verifiers.forEach { verifier ->
                    assertTrue(verifier.verifySignature(data, signature), "Verify")

                    generators.forEach { generator ->
                        assertTrue(verifier.verifySignature(data, generator.generateSignature(data)), "Sign-Verify")
                    }
                }
            }
        }
    }
}
