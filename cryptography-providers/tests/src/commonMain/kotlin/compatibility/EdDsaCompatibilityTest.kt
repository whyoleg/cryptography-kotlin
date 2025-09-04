/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.compatibility

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import dev.whyoleg.cryptography.providers.tests.compatibility.api.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.serialization.pem.*
import kotlinx.io.bytestring.*
import kotlinx.serialization.*
import kotlin.test.*

private val edPublicKeyFormats = listOf(
    EdDSA.PublicKey.Format.JWK,
    EdDSA.PublicKey.Format.RAW,
    EdDSA.PublicKey.Format.DER,
    EdDSA.PublicKey.Format.PEM,
).associateBy { it.name }

private val edPrivateKeyFormats = listOf(
    EdDSA.PrivateKey.Format.JWK,
    EdDSA.PrivateKey.Format.RAW,
    EdDSA.PrivateKey.Format.DER,
    EdDSA.PrivateKey.Format.PEM,
).associateBy { it.name }

abstract class EdDsaCompatibilityTest(
    provider: CryptographyProvider,
) : CompatibilityTest<EdDSA>(EdDSA, provider) {

    @Serializable
    private data class KeyParameters(val curveName: String) : TestParameters {
        val curve: EdDSA.Curve
            get() = when (curveName) {
                EdDSA.Curve.Ed25519.name -> EdDSA.Curve.Ed25519
                EdDSA.Curve.Ed448.name   -> EdDSA.Curve.Ed448
                else -> error("Unsupported curve: $curveName")
            }
    }

    override suspend fun CompatibilityTestScope<EdDSA>.generate(isStressTest: Boolean) {
        val signatureIterations = if (isStressTest) 5 else 2

        listOf(EdDSA.Curve.Ed25519, EdDSA.Curve.Ed448).forEach { curve ->
            if (!supportsAlgorithmOnCurve(curve)) return@forEach

            val keyParametersId = api.keyPairs.saveParameters(KeyParameters(curve.name))

            val keyIterations = if (isStressTest) 5 else 2
            algorithm.keyPairGenerator(curve).generateKeys(keyIterations) { keyPair ->
                val keyReference = api.keyPairs.saveData(
                    keyParametersId,
                    KeyPairData(
                        public = KeyData(keyPair.publicKey.encodeTo(edPublicKeyFormats.values, ::supportsKeyFormat)),
                        private = KeyData(keyPair.privateKey.encodeTo(edPrivateKeyFormats.values, ::supportsKeyFormat)),
                    )
                )

                repeat(signatureIterations) {
                    val dataSize = CryptographyRandom.nextInt(0, 8192)
                    val data = ByteString(CryptographyRandom.nextBytes(dataSize))
                    val signature = keyPair.privateKey.signatureGenerator().generateSignature(data)

                    api.signatures.saveData(
                        parametersId = api.signatures.saveParameters(TestParameters.Empty),
                        data = SignatureData(keyReference, data, signature)
                    )
                }
            }
        }
    }

    private fun ProviderTestScope.supportsAlgorithmOnCurve(curve: EdDSA.Curve): Boolean {
        // no per-curve gating at the moment; provider-level SupportedAlgorithmsTest already checks availability
        return true
    }

    override suspend fun CompatibilityTestScope<EdDSA>.validate() {
        // Decode saved keys
        val keyPairs = buildMap {
            api.keyPairs.getParameters<KeyParameters> { params, parametersId, _ ->
                val publicKeyDecoder = algorithm.publicKeyDecoder(params.curve)
                val privateKeyDecoder = algorithm.privateKeyDecoder(params.curve)
                api.keyPairs.getData<KeyPairData>(parametersId) { (public, private), keyReference, _ ->
                    val publicKeys = publicKeyDecoder.decodeFrom(
                        formats = public.formats,
                        formatOf = edPublicKeyFormats::getValue,
                        supports = ::supportsKeyFormat
                    ) { key, format, bytes ->
                        when (format) {
                            EdDSA.PublicKey.Format.JWK -> {}
                            EdDSA.PublicKey.Format.PEM -> {
                                val expected = PemDocument.decode(bytes)
                                val actual = PemDocument.decode(key.encodeToByteString(format))
                                assertEquals(expected.label, actual.label)
                                assertEquals(PemLabel.PublicKey, actual.label)
                                assertContentEquals(expected.content, actual.content, "Public Key $format content encoding")
                            }
                            else -> assertContentEquals(bytes, key.encodeToByteString(format), "Public Key $format encoding")
                        }
                    }
                    val privateKeys = privateKeyDecoder.decodeFrom(
                        formats = private.formats,
                        formatOf = edPrivateKeyFormats::getValue,
                        supports = ::supportsKeyFormat
                    ) { key, format, bytes ->
                        when (format) {
                            EdDSA.PrivateKey.Format.JWK -> {}
                            EdDSA.PrivateKey.Format.PEM -> {
                                val expected = PemDocument.decode(bytes)
                                val actual = PemDocument.decode(key.encodeToByteString(format))
                                assertEquals(expected.label, actual.label)
                                assertEquals(PemLabel.PrivateKey, actual.label)
                                assertContentEquals(expected.content, actual.content, "Private Key $format content encoding")
                            }
                            else -> assertContentEquals(bytes, key.encodeToByteString(format), "Private Key $format encoding")
                        }
                    }
                    put(keyReference, publicKeys to privateKeys)
                }
            }
        }

        // Validate signatures across providers
        api.signatures.getParameters<TestParameters.Empty> { _, parametersId, _ ->
            api.signatures.getData<SignatureData>(parametersId) { (keyReference, data, signature), _, _ ->
                val (publicKeys, privateKeys) = keyPairs[keyReference] ?: return@getData
                val verifiers = publicKeys.map { it.signatureVerifier() }
                val generators = privateKeys.map { it.signatureGenerator() }

                verifiers.forEach { verifier ->
                    assertTrue(verifier.tryVerifySignature(data, signature), "Verify")
                    generators.forEach { generator ->
                        val s = generator.generateSignature(data)
                        assertTrue(verifier.tryVerifySignature(data, s), "Sign-Verify")
                    }
                }
            }
        }
    }
}
