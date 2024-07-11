/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.algorithms.asymmetric

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.providers.tests.api.*
import dev.whyoleg.cryptography.providers.tests.api.compatibility.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.pem.*
import kotlinx.serialization.*
import kotlin.test.*

private val publicKeyFormats = listOf(
    EC.PublicKey.Format.JWK,
    EC.PublicKey.Format.RAW,
    EC.PublicKey.Format.DER,
    EC.PublicKey.Format.PEM,
).associateBy { it.name }

private val privateKeyFormats = listOf(
    EC.PrivateKey.Format.JWK,
    EC.PrivateKey.Format.DER,
    EC.PrivateKey.Format.PEM,
    EC.PrivateKey.Format.DER.SEC1,
    EC.PrivateKey.Format.PEM.SEC1,
).associateBy { it.name }

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

    override suspend fun CompatibilityTestScope<ECDSA>.generate(isStressTest: Boolean) {
        val keyIterations = when {
            isStressTest -> 5
            else         -> 2
        }
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
            algorithm.keyPairGenerator(curve).generateKeys(keyIterations) { keyPair ->
                val keyReference = api.keyPairs.saveData(
                    keyParametersId, KeyPairData(
                        public = KeyData(keyPair.publicKey.encodeTo(publicKeyFormats.values, ::supportsKeyFormat)),
                        private = KeyData(keyPair.privateKey.encodeTo(privateKeyFormats.values, ::supportsKeyFormat))
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
                        formatOf = publicKeyFormats::getValue,
                        supports = ::supportsKeyFormat
                    ) { key, format, bytes ->
                        when (format) {
                            EC.PublicKey.Format.JWK -> {}
                            EC.PublicKey.Format.RAW,
                            EC.PublicKey.Format.DER,
                            EC.PublicKey.Format.PEM,
                                                    -> {
                                assertContentEquals(bytes, key.encodeTo(format), "Public Key $format encoding")
                            }
                        }
                    }
                    val privateKeys = privateKeyDecoder.decodeFrom(
                        formats = private.formats,
                        formatOf = privateKeyFormats::getValue,
                        supports = ::supportsKeyFormat
                    ) { key, format, bytes ->
                        when (format) {
                            EC.PrivateKey.Format.JWK      -> {}
                            EC.PrivateKey.Format.DER.SEC1 -> {
                                assertEcPrivateKeyEquals(bytes, key.encodeTo(format))
                            }
                            EC.PrivateKey.Format.PEM.SEC1 -> {
                                val expected = PEM.decode(bytes)
                                val actual = PEM.decode(key.encodeTo(format))

                                assertEquals(expected.label, actual.label)

                                assertEcPrivateKeyEquals(expected.bytes, actual.bytes)
                            }
                            EC.PrivateKey.Format.DER      -> {
                                assertPkcs8EcPrivateKeyEquals(bytes, key.encodeTo(format))
                            }
                            EC.PrivateKey.Format.PEM      -> {
                                val expected = PEM.decode(bytes)
                                val actual = PEM.decode(key.encodeTo(format))

                                assertEquals(expected.label, actual.label)

                                assertPkcs8EcPrivateKeyEquals(expected.bytes, actual.bytes)
                            }
                        }
                    }
                    put(keyReference, publicKeys to privateKeys)
                }
            }
        }

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

private fun assertEcPrivateKeyEquals(
    expectedBytes: ByteArray,
    actualBytes: ByteArray,
    requireParametersCheck: Boolean = true,
) {
    val expected = DER.decodeFromByteArray(EcPrivateKey.serializer(), expectedBytes)
    val actual = DER.decodeFromByteArray(EcPrivateKey.serializer(), actualBytes)

    assertEquals(expected.version, actual.version, "EcPrivateKey.version")
    assertContentEquals(expected.privateKey, actual.privateKey, "EcPrivateKey.privateKey")

    if (requireParametersCheck || expected.parameters != null && actual.parameters != null) {
        assertEquals(expected.parameters, actual.parameters, "EcPrivateKey.parameters")
    }

    if (expected.publicKey != null && actual.publicKey != null) {
        assertEquals(expected.publicKey?.unusedBits, actual.publicKey?.unusedBits, "EcPrivateKey.publicKey.unusedBits")
        assertContentEquals(expected.publicKey?.byteArray, actual.publicKey?.byteArray, "EcPrivateKey.publicKey.byteArray")
    }
}

private fun assertPkcs8EcPrivateKeyEquals(expectedBytes: ByteArray, actualBytes: ByteArray) {
    val expected = DER.decodeFromByteArray(PrivateKeyInfo.serializer(), expectedBytes)
    val actual = DER.decodeFromByteArray(PrivateKeyInfo.serializer(), actualBytes)

    assertEquals(expected.version, actual.version, "PrivateKeyInfo.version")
    val expectedAlgorithm = assertIs<EcKeyAlgorithmIdentifier>(expected.privateKeyAlgorithm)
    val actualAlgorithm = assertIs<EcKeyAlgorithmIdentifier>(actual.privateKeyAlgorithm)
    assertEquals(expectedAlgorithm.parameters, actualAlgorithm.parameters, "PrivateKeyInfo.parameters")

    assertEcPrivateKeyEquals(
        expectedBytes = expected.privateKey,
        actualBytes = actual.privateKey,
        // different providers could encode or not encode parameters inside
        requireParametersCheck = false
    )
}
