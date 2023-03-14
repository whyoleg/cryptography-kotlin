/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.compatibility

import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.test.utils.*
import dev.whyoleg.cryptography.tests.compatibility.api.*
import kotlinx.serialization.*
import kotlin.test.*

private const val keyIterations = 5
private const val signatureIterations = 5
private const val maxDataSize = 10000

private inline fun generateCurves(block: (curve: EC.Curve) -> Unit) {
    generate(block, EC.Curve.P256, EC.Curve.P384, EC.Curve.P521)
}

class EcdsaTest : CompatibilityTest<ECDSA>(ECDSA) {
    @Serializable
    private data class KeyParameters(val curveName: String) : TestParameters {
        val curve
            get() = when (curveName) {
                EC.Curve.P256.name -> EC.Curve.P256
                EC.Curve.P384.name -> EC.Curve.P384
                EC.Curve.P521.name -> EC.Curve.P521
                else               -> error("Unknown curve: $curveName")
            }
    }

    @Serializable
    private data class SignatureParameters(
        val digest: String,
        val signatureFormat: ECDSA.SignatureFormat,
    ) : TestParameters

    override suspend fun CompatibilityTestContext<ECDSA>.generate() {
        val signatureParametersList = buildList {
            listOf(ECDSA.SignatureFormat.RAW, ECDSA.SignatureFormat.DER).forEach { signatureFormat ->
                if (!supportsSignatureFormat(signatureFormat)) return@forEach

                generateDigests { digest, _ ->
                    val parameters = SignatureParameters(digest.name, signatureFormat)
                    val id = api.signatures.saveParameters(parameters)
                    add(id to parameters)
                }
            }
        }
        generateCurves { curve ->
            val keyParametersId = api.keyPairs.saveParameters(KeyParameters(curve.name))
            algorithm.keyPairGenerator(curve).generateKeys(keyIterations) { keyPair ->
                val keyReference = api.keyPairs.saveData(
                    keyParametersId, KeyPairData(
                        public = KeyData(keyPair.publicKey.encodeTo(EC.PublicKey.Format.values(), ::supportsKeyFormat)),
                        private = KeyData(keyPair.privateKey.encodeTo(EC.PrivateKey.Format.values(), ::supportsKeyFormat))
                    )
                )

                signatureParametersList.forEach { (signatureParametersId, signatureParameters) ->
                    logger.log { "digest = ${signatureParameters.digest}, signatureFormat = ${signatureParameters.signatureFormat}" }
                    val signer =
                        keyPair.privateKey.signatureGenerator(digest(signatureParameters.digest), signatureParameters.signatureFormat)
                    val verifier =
                        keyPair.publicKey.signatureVerifier(digest(signatureParameters.digest), signatureParameters.signatureFormat)

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

    override suspend fun CompatibilityTestContext<ECDSA>.validate() {
        val keyPairs = buildMap {
            api.keyPairs.getParameters<KeyParameters> { keyParameters, parametersId ->
                val privateKeyDecoder = algorithm.privateKeyDecoder(keyParameters.curve)
                val publicKeyDecoder = algorithm.publicKeyDecoder(keyParameters.curve)

                api.keyPairs.getData<KeyPairData>(parametersId) { (public, private), keyReference ->
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
                                if (supportsPrivateKeyDerComparison()) {
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

        api.signatures.getParameters<SignatureParameters> { (digestName, signatureFormat), parametersId ->
            if (!supportsSignatureFormat(signatureFormat)) return@getParameters

            val digest = digest(digestName)
            api.signatures.getData<SignatureData>(parametersId) { (keyReference, data, signature), _ ->
                val (publicKeys, privateKeys) = keyPairs.getValue(keyReference)
                val verifiers = publicKeys.map { it.signatureVerifier(digest, signatureFormat) }
                val generators = privateKeys.map { it.signatureGenerator(digest, signatureFormat) }

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
