/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.compatibility

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import dev.whyoleg.cryptography.providers.tests.compatibility.api.*
import dev.whyoleg.cryptography.random.*
import kotlinx.io.bytestring.*
import kotlinx.serialization.*

private const val maxDataSize = 10000

abstract class EcdsaCompatibilityTest(
    provider: CryptographyProvider,
) : EcCompatibilityTest<ECDSA.PublicKey, ECDSA.PrivateKey, ECDSA.KeyPair, ECDSA>(ECDSA, provider) {

    @Serializable
    private data class SignatureParameters(
        val digestName: String?,
        val signatureFormat: ECDSA.SignatureFormat,
    ) : TestParameters {
        val digest get() = digestName?.let(::digest)
    }

    override suspend fun CompatibilityTestScope<ECDSA>.generate(isStressTest: Boolean) {
        val signatureIterations = when {
            isStressTest -> 5
            else         -> 2
        }

        val signatureParametersList = buildList {
            listOf(ECDSA.SignatureFormat.RAW, ECDSA.SignatureFormat.DER).forEach { signatureFormat ->
                (DigestsForCompatibility + listOf(null)).forEach { digest ->
                    if (!supportsSignatureDigest(digest)) return@forEach

                    val parameters = SignatureParameters(digest?.name, signatureFormat)
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
            ) { keyPair, keyReference, _ ->
                signatureParametersList.forEach { (signatureParametersId, signatureParameters) ->
                    logger.log { "digest = ${signatureParameters.digestName}, signatureFormat = ${signatureParameters.signatureFormat}" }
                    val signer =
                        keyPair.privateKey.signatureGenerator(signatureParameters.digest, signatureParameters.signatureFormat)
                    val verifier =
                        keyPair.publicKey.signatureVerifier(signatureParameters.digest, signatureParameters.signatureFormat)
                    val verifier2 =
                        keyPair.privateKey.getPublicKey().signatureVerifier(signatureParameters.digest, signatureParameters.signatureFormat)

                    repeat(signatureIterations) {
                        val dataSize = CryptographyRandom.nextInt(maxDataSize)
                        logger.log { "data.size      = $dataSize" }
                        val data = ByteString(CryptographyRandom.nextBytes(dataSize))
                        val signature = signer.generateSignature(data)
                        logger.log { "signature.size = ${signature.size}" }

                        verifier.assertVerifySignature(data, signature, "Initial Verify")
                        verifier2.assertVerifySignature(data, signature, "Initial Verify (inferred public key)")

                        api.signatures.saveData(signatureParametersId, SignatureData(keyReference, data, signature))
                    }
                }
            }
        }
    }

    override suspend fun CompatibilityTestScope<ECDSA>.validate() {
        val keyPairs = validateKeys()

        api.signatures.getParameters<SignatureParameters> { signatureParameters, parametersId, _ ->
            if (!supportsSignatureDigest(signatureParameters.digest)) return@getParameters

            api.signatures.getData<SignatureData>(parametersId) { (keyReference, data, signature), _, _ ->
                val (publicKeys, privateKeys) = keyPairs[keyReference] ?: return@getData
                val verifiers = publicKeys.map { it.signatureVerifier(signatureParameters.digest, signatureParameters.signatureFormat) }
                val verifiers2 = privateKeys.mapNotNull {
                    val publicKey = getPublicKey(it)
                    publicKey?.signatureVerifier(signatureParameters.digest, signatureParameters.signatureFormat)
                }
                val generators = privateKeys.map { it.signatureGenerator(signatureParameters.digest, signatureParameters.signatureFormat) }

                verifiers.forEach { verifier ->
                    verifier.assertVerifySignature(data, signature, "Verify")
                }

                verifiers2.forEach { verifier ->
                    verifier.assertVerifySignature(data, signature, "Verify (inferred public key)")
                }

                generators.forEach { generator ->
                    val signature = generator.generateSignature(data)
                    verifiers.forEach { verifier ->
                        verifier.assertVerifySignature(data, signature, "Sign-Verify")
                    }
                    verifiers2.forEach { verifier ->
                        verifier.assertVerifySignature(data, signature, "Sign-Verify (inferred public key)")
                    }
                }
            }
        }
    }
}
