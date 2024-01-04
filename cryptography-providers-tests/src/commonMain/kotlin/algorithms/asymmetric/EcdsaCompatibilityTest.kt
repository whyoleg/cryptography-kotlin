/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.algorithms.asymmetric

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.providers.tests.api.*
import dev.whyoleg.cryptography.providers.tests.api.compatibility.*
import dev.whyoleg.cryptography.random.*
import kotlinx.serialization.*
import kotlin.test.*

private const val keyIterations = 3
private const val signatureIterations = 3
private const val maxDataSize = 10000

private inline fun generateCurves(block: (curve: EC.Curve) -> Unit) {
    generate(block, EC.Curve.P256, EC.Curve.P384, EC.Curve.P521, EC.Curve("secp256k1"))
}

abstract class EcdsaCompatibilityTest(provider: CryptographyProvider) : CompatibilityTest<ECDSA>(ECDSA, provider) {
    @Serializable
    private data class KeyParameters(val curveName: String) : TestParameters {
        val curve get() = EC.Curve(curveName)
    }

    @Serializable
    private data class SignatureParameters(
        val digestName: String,
        val signatureFormat: ECDSA.SignatureFormat,
    ) : TestParameters {
        val digest get() = digest(digestName)
    }

    override suspend fun CompatibilityTestScope<ECDSA>.generate() {
        val signatureParametersList = buildList {
            listOf(ECDSA.SignatureFormat.RAW, ECDSA.SignatureFormat.DER).forEach { signatureFormat ->
                if (!supportsSignatureFormat(signatureFormat)) return@forEach

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
            algorithm.keyPairGenerator(curve).generateKeys(keyIterations) { keyPair ->
                val keyReference = api.keyPairs.saveData(
                    keyParametersId, KeyPairData(
                        public = KeyData(keyPair.publicKey.encodeTo(EC.PublicKey.Format.entries, ::supportsKeyFormat)),
                        private = KeyData(keyPair.privateKey.encodeTo(EC.PrivateKey.Format.entries, ::supportsKeyFormat))
                    )
                )

                signatureParametersList.forEach { (signatureParametersId, signatureParameters) ->
                    logger.log { "digest = ${signatureParameters.digestName}, signatureFormat = ${signatureParameters.signatureFormat}" }
                    val signer =
                        keyPair.privateKey.signatureGenerator(signatureParameters.digest, signatureParameters.signatureFormat)
                    val verifier =
                        keyPair.publicKey.signatureVerifier(signatureParameters.digest, signatureParameters.signatureFormat)

                    repeat(signatureIterations) {
                        val dataSize = CryptographyRandom.nextInt(maxDataSize)
                        logger.log { "data.size      = $dataSize" }
                        val data = CryptographyRandom.nextBytes(dataSize)
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
        val keyPairs = buildMap {
            api.keyPairs.getParameters<KeyParameters> { keyParameters, parametersId, _ ->
                if (!supportsCurve(keyParameters.curve)) return@getParameters

                val privateKeyDecoder = algorithm.privateKeyDecoder(keyParameters.curve)
                val publicKeyDecoder = algorithm.publicKeyDecoder(keyParameters.curve)

                api.keyPairs.getData<KeyPairData>(parametersId) { (public, private), keyReference, otherContext ->
                    val publicKeys = publicKeyDecoder.decodeFrom(
                        formats = public.formats,
                        formatOf = EC.PublicKey.Format::valueOf,
                        supports = ::supportsKeyFormat
                    ) { key, format, bytes ->
                        when (format) {
                            EC.PublicKey.Format.RAW, EC.PublicKey.Format.DER, EC.PublicKey.Format.PEM -> {
                                assertContentEquals(bytes, key.encodeTo(format), "Public Key $format encoding")
                            }
                            EC.PublicKey.Format.JWK                                                   -> {}
                        }
                    }
                    val privateKeys = privateKeyDecoder.decodeFrom(
                        formats = private.formats,
                        formatOf = EC.PrivateKey.Format::valueOf,
                        supports = ::supportsKeyFormat
                    ) { key, format, bytes ->
                        when (format) {
                            EC.PrivateKey.Format.DER, EC.PrivateKey.Format.PEM -> {
                                if (supportsPrivateKeyDerComparisonWith(otherContext)) {
                                    assertContentEquals(bytes, key.encodeTo(format), "Private Key $format encoding")
                                }
                            }
                            EC.PrivateKey.Format.JWK                           -> {}
                        }
                    }
                    put(keyReference, publicKeys to privateKeys)
                }
            }
        }

        api.signatures.getParameters<SignatureParameters> { signatureParameters, parametersId, _ ->
            if (!supportsSignatureFormat(signatureParameters.signatureFormat)) return@getParameters
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
