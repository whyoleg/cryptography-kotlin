/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
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

private const val maxDataSize = 10000

private val publicKeyFormats = listOf(
    EdDSA.PublicKey.Format.JWK,
    EdDSA.PublicKey.Format.RAW,
    EdDSA.PublicKey.Format.DER,
    EdDSA.PublicKey.Format.PEM,
).associateBy { it.name }

private val privateKeyFormats = listOf(
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
        val curve get() = EdDSA.Curve.valueOf(curveName)
    }

    override suspend fun CompatibilityTestScope<EdDSA>.generate(isStressTest: Boolean) {
        val signatureParametersId = api.signatures.saveParameters(TestParameters.Empty)
        val signatureIterations = when {
            isStressTest -> 5
            else         -> 2
        }

        EdDSA.Curve.entries.forEach { curve ->
            if (!supportsCurve(curve)) return@forEach

            val keyParametersId = api.keyPairs.saveParameters(KeyParameters(curve.name))
            generateKeys(
                curve = curve,
                keyParametersId = keyParametersId,
                isStressTest = isStressTest
            ) { keyPair, keyReference ->
                val signer = keyPair.privateKey.signatureGenerator()
                val verifier = keyPair.publicKey.signatureVerifier()
                val verifier2 = keyPair.privateKey.getPublicKey().signatureVerifier()

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

    override suspend fun CompatibilityTestScope<EdDSA>.validate() {
        val keyPairs = validateKeys()

        api.signatures.getParameters<TestParameters.Empty> { _, parametersId, _ ->
            api.signatures.getData<SignatureData>(parametersId) { (keyReference, data, signature), _, _ ->
                val (publicKeys, privateKeys) = keyPairs[keyReference] ?: return@getData
                val verifiers = publicKeys.map { it.signatureVerifier() }
                val verifiers2 = privateKeys.mapNotNull {
                    val publicKey = getPublicKey(it)
                    publicKey?.signatureVerifier()
                }
                val generators = privateKeys.map { it.signatureGenerator() }

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

    private suspend fun CompatibilityTestScope<EdDSA>.generateKeys(
        curve: EdDSA.Curve,
        keyParametersId: TestParametersId,
        isStressTest: Boolean,
        block: suspend (keyPair: EdDSA.KeyPair, keyReference: TestReference) -> Unit,
    ) {
        val keyIterations = when {
            isStressTest -> 5
            else         -> 2
        }

        algorithm.keyPairGenerator(curve).generateKeys(keyIterations) { keyPair ->
            val publicKeyData = KeyData(keyPair.publicKey.encodeTo(publicKeyFormats.values, ::supportsKeyFormat))
            val privateKeyData = KeyData(keyPair.privateKey.encodeTo(privateKeyFormats.values, ::supportsKeyFormat))

            assertEquals(
                publicKeyData.formats,
                keyPair.privateKey.getPublicKey().encodeTo(publicKeyFormats.values, ::supportsKeyFormat),
            )

            val keyReference = api.keyPairs.saveData(keyParametersId, KeyPairData(publicKeyData, privateKeyData))

            block(keyPair, keyReference)
        }
    }


    private suspend fun verifyPublicKey(
        publicKey: EdDSA.PublicKey,
        format: EdDSA.PublicKey.Format,
        expected: ByteString,
    ) {
        when (format) {
            EdDSA.PublicKey.Format.JWK -> {}
            EdDSA.PublicKey.Format.RAW,
            EdDSA.PublicKey.Format.DER,
                                       -> {
                assertContentEquals(expected, publicKey.encodeToByteString(format), "Public Key $format encoding")
            }
            EdDSA.PublicKey.Format.PEM -> {
                val expected = PemDocument.decode(expected)
                val actual = PemDocument.decode(publicKey.encodeToByteString(format))

                assertEquals(expected.label, actual.label)
                assertEquals(PemLabel.PublicKey, actual.label)
                assertContentEquals(expected.content, actual.content, "Public Key $format content encoding")
            }
        }
    }

    protected suspend fun CompatibilityTestScope<EdDSA>.validateKeys() = buildMap {
        api.keyPairs.getParameters<KeyParameters> { keyParameters, parametersId, _ ->
            if (!supportsCurve(keyParameters.curve)) return@getParameters

            val privateKeyDecoder = algorithm.privateKeyDecoder(keyParameters.curve)
            val publicKeyDecoder = algorithm.publicKeyDecoder(keyParameters.curve)

            api.keyPairs.getData<KeyPairData>(parametersId) { (public, private), keyReference, otherContext ->
                val publicKeys = publicKeyDecoder.decodeFrom(
                    formats = public.formats,
                    formatOf = publicKeyFormats::getValue,
                    supports = ::supportsKeyFormat,
                    validate = ::verifyPublicKey
                )
                val privateKeys = privateKeyDecoder.decodeFrom(
                    formats = private.formats,
                    formatOf = privateKeyFormats::getValue,
                    supports = ::supportsKeyFormat,
                    supportsDecoding = { f, b -> supportsPrivateKeyDecoding(f, b, otherContext) }
                ) { key, format, byteString ->

                    getPublicKey(key)?.let { publicKey ->
                        public.formats.filterSupportedFormats(
                            formatOf = publicKeyFormats::getValue,
                            supports = ::supportsKeyFormat,
                        ).forEach { (format, bytes) ->
                            verifyPublicKey(publicKey, format, bytes)
                        }
                    }

                    when (format) {
                        EdDSA.PrivateKey.Format.JWK -> {}
                        EdDSA.PrivateKey.Format.RAW -> {
                            assertContentEquals(byteString, key.encodeToByteString(format))
                        }
                        EdDSA.PrivateKey.Format.DER -> {
                            assertPrivateKeyInfoEquals(byteString, key.encodeToByteString(format))
                        }
                        EdDSA.PrivateKey.Format.PEM -> {
                            val expected = PemDocument.decode(byteString)
                            val actual = PemDocument.decode(key.encodeToByteString(format))

                            assertEquals(expected.label, actual.label)
                            assertEquals(PemLabel.PrivateKey, actual.label)

                            assertPrivateKeyInfoEquals(expected.content, actual.content)
                        }
                    }
                }
                put(keyReference, publicKeys to privateKeys)
            }
        }
    }

    private suspend fun AlgorithmTestScope<EdDSA>.getPublicKey(privateKey: EdDSA.PrivateKey): EdDSA.PublicKey? = try {
        privateKey.getPublicKey()
    } catch (cause: Throwable) {
        if (!supportsPublicKeyAccess(cause)) null
        else throw cause
    }
}
