/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.compatibility

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import dev.whyoleg.cryptography.providers.tests.compatibility.api.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.serialization.pem.*
import kotlinx.io.bytestring.*
import kotlinx.serialization.*
import kotlin.test.*

private const val maxDataSize = 10_000

private val parametersFormats = listOf(
    DSA.Parameters.Format.DER,
    DSA.Parameters.Format.PEM,
).associateBy { it.name }

private val publicKeyFormats = listOf(
    DSA.PublicKey.Format.DER,
    DSA.PublicKey.Format.PEM,
).associateBy { it.name }

private val privateKeyFormats = listOf(
    DSA.PrivateKey.Format.DER,
    DSA.PrivateKey.Format.PEM,
).associateBy { it.name }

abstract class DsaCompatibilityTest(
    provider: CryptographyProvider,
) : CompatibilityTest<DSA>(DSA, provider) {

    @Serializable
    private data class DsaKeyParameters(
        val parameters: KeyData,
    ) : TestParameters

    @Serializable
    private data class SignatureParameters(
        val digestName: String?,
        val signatureFormat: DSA.SignatureFormat = DSA.SignatureFormat.DER,
    ) : TestParameters {
        val digest: CryptographyAlgorithmId<Digest>? get() = digestName?.let(::digest)
    }

    private suspend fun verifyParameters(
        parameters: DSA.Parameters,
        format: DSA.Parameters.Format,
        expected: ByteString,
    ) {
        when (format) {
            DSA.Parameters.Format.DER -> {
                assertContentEquals(expected, parameters.encodeToByteString(format))
            }
            DSA.Parameters.Format.PEM -> {
                val expectedDoc = PemDocument.decode(expected)
                val actualDoc = PemDocument.decode(parameters.encodeToByteString(format))

                assertEquals(expectedDoc.label, actualDoc.label)
                assertEquals(PemLabel.DsaParameters, actualDoc.label)
                assertContentEquals(expectedDoc.content, actualDoc.content)
            }
        }
    }

    private suspend fun verifyPublicKey(
        publicKey: DSA.PublicKey,
        format: DSA.PublicKey.Format,
        expected: ByteString,
    ) {
        when (format) {
            DSA.PublicKey.Format.DER -> {
                assertContentEquals(expected, publicKey.encodeToByteString(format))
            }
            DSA.PublicKey.Format.PEM -> {
                val expectedDoc = PemDocument.decode(expected)
                val actualDoc = PemDocument.decode(publicKey.encodeToByteString(format))

                assertEquals(expectedDoc.label, actualDoc.label)
                assertEquals(PemLabel.PublicKey, actualDoc.label)
                assertContentEquals(expectedDoc.content, actualDoc.content)
            }
        }
    }

    private suspend fun verifyPrivateKey(
        privateKey: DSA.PrivateKey,
        format: DSA.PrivateKey.Format,
        expected: ByteString,
    ) {
        when (format) {
            DSA.PrivateKey.Format.DER -> {
                assertContentEquals(expected, privateKey.encodeToByteString(format))
            }
            DSA.PrivateKey.Format.PEM -> {
                val expectedDoc = PemDocument.decode(expected)
                val actualDoc = PemDocument.decode(privateKey.encodeToByteString(format))

                assertEquals(expectedDoc.label, actualDoc.label)
                assertEquals(PemLabel.PrivateKey, actualDoc.label)

                assertContentEquals(expectedDoc.content, actualDoc.content)
            }
        }
    }

    override suspend fun CompatibilityTestScope<DSA>.generate(isStressTest: Boolean) {
        val parameterIterations = if (isStressTest) 5 else 2
        val keyIterations = if (isStressTest) 5 else 2
        val signatureIterations = if (isStressTest) 5 else 2

        data class DsaCase(
            val primeSizeBits: Int,
            val subprimeSizeBits: Int?,
            val maxDigestBits: Int,
        )

        // FIPS 186-2: (1024, 160)
        // FIPS 186-4: (2048, 224), (2048, 256), (3072, 256)
        val parameters = listOf(
            DsaCase(primeSizeBits = 1024, subprimeSizeBits = null, maxDigestBits = 160),
            DsaCase(primeSizeBits = 2048, subprimeSizeBits = null, maxDigestBits = 224),
            DsaCase(primeSizeBits = 3072, subprimeSizeBits = null, maxDigestBits = 256),
            DsaCase(primeSizeBits = 2048, subprimeSizeBits = 256, maxDigestBits = 256),
        )

        val digests: List<CryptographyAlgorithmId<Digest>?> = DigestsForCompatibility + listOf(null)

        parameters.forEach { (primeSizeBits, subprimeSizeBits, maxDigestBits) ->
            if (!supportsDsaParameters(subprimeSizeBits)) return@forEach

            val dsaParameters = buildList {
                val generator = algorithm.parametersGenerator(primeSizeBits.bits, subprimeSizeBits?.bits)
                repeat(parameterIterations) {
                    add(generator.generateParameters())
                }
            }

            dsaParameters.forEach { parameters ->
                val keyParametersId = api.keyPairs.saveParameters(
                    DsaKeyParameters(KeyData(parameters.encodeTo(parametersFormats.values, ::supportsFormat)))
                )

                digests.forEach digests@{ digest ->
                    if (digest != null && digest.digestSize() * 8 < maxDigestBits) return@digests
                    if (!supportsDsaSignatureDigest(digest)) return@digests

                    listOf(DSA.SignatureFormat.DER, DSA.SignatureFormat.RAW).forEach { signatureFormat ->
                        val sigParams = SignatureParameters(digestName = digest?.name, signatureFormat = signatureFormat)
                        val signatureParametersId = api.signatures.saveParameters(sigParams)

                        generateKeys(parameters, keyParametersId, keyIterations) { keyPair, keyReference ->
                            val signer = keyPair.privateKey.signatureGenerator(sigParams.digest, sigParams.signatureFormat)
                            val verifier = keyPair.publicKey.signatureVerifier(sigParams.digest, sigParams.signatureFormat)

                            repeat(signatureIterations) {
                                val dataSize = CryptographyRandom.nextInt(maxDataSize)
                                val data = ByteString(CryptographyRandom.nextBytes(dataSize))
                                val signature = signer.generateSignature(data)

                                verifier.assertVerifySignature(data, signature, "Initial Verify")

                                api.signatures.saveData(
                                    parametersId = signatureParametersId,
                                    data = SignatureData(keyReference, data, signature)
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    private suspend fun CompatibilityTestScope<DSA>.generateKeys(
        parameters: DSA.Parameters,
        keyParametersId: TestParametersId,
        keyIterations: Int,
        block: suspend (keyPair: DSA.KeyPair, keyReference: TestReference) -> Unit,
    ) {
        parameters.keyPairGenerator().generateKeys(keyIterations) { keyPair ->
            val publicKeyData = KeyData(keyPair.publicKey.encodeTo(publicKeyFormats.values, ::supportsFormat))
            val privateKeyData = KeyData(keyPair.privateKey.encodeTo(privateKeyFormats.values, ::supportsFormat))

            assertEquals(
                publicKeyData.formats,
                keyPair.privateKey.getPublicKey().encodeTo(publicKeyFormats.values, ::supportsFormat),
            )

            val keyReference = api.keyPairs.saveData(keyParametersId, KeyPairData(publicKeyData, privateKeyData))

            block(keyPair, keyReference)
        }
    }

    override suspend fun CompatibilityTestScope<DSA>.validate() {
        val keyPairs = validateKeys()

        api.signatures.getParameters<SignatureParameters> { sigParams, parametersId, _ ->
            if (!supportsDsaSignatureDigest(sigParams.digest)) return@getParameters

            api.signatures.getData<SignatureData>(parametersId) { (keyReference, data, signature), _, _ ->
                val (publicKeys, privateKeys) = keyPairs[keyReference] ?: return@getData

                val verifiers = publicKeys.map { it.signatureVerifier(sigParams.digest, sigParams.signatureFormat) }
                val generators = privateKeys.map { it.signatureGenerator(sigParams.digest, sigParams.signatureFormat) }

                verifiers.forEach { verifier ->
                    verifier.assertVerifySignature(data, signature, "Verify")
                }

                generators.forEach { generator ->
                    val sig2 = generator.generateSignature(data)
                    verifiers.forEach { verifier ->
                        verifier.assertVerifySignature(data, sig2, "Sign-Verify")
                    }
                }
            }
        }
    }

    private suspend fun CompatibilityTestScope<DSA>.validateKeys() = buildMap {
        api.keyPairs.getParameters<DsaKeyParameters> { keyParameters, parametersId, _ ->
            val parametersDecoder = algorithm.parametersDecoder()
            keyParameters.parameters.formats.filterSupportedFormats(
                formatOf = parametersFormats::getValue,
                supports = ::supportsFormat,
            ).forEach { (format, bytes) ->
                val decoded = parametersDecoder.decodeFromByteString(format, bytes)
                verifyParameters(decoded, format, bytes)
            }

            val publicKeyDecoder = algorithm.publicKeyDecoder()
            val privateKeyDecoder = algorithm.privateKeyDecoder()

            api.keyPairs.getData<KeyPairData>(parametersId) { (public, private), keyReference, _ ->
                val publicKeys = publicKeyDecoder.decodeFrom(
                    formats = public.formats,
                    formatOf = publicKeyFormats::getValue,
                    supports = ::supportsFormat,
                    validate = ::verifyPublicKey
                )

                val privateKeys = privateKeyDecoder.decodeFrom(
                    formats = private.formats,
                    formatOf = privateKeyFormats::getValue,
                    supports = ::supportsFormat,
                ) { key, format, byteString ->
                    verifyPrivateKey(key, format, byteString)

                    getPublicKey(key)?.let { publicKey ->
                        public.formats.filterSupportedFormats(
                            formatOf = publicKeyFormats::getValue,
                            supports = ::supportsFormat,
                        ).forEach { (pubFormat, expectedPubBytes) ->
                            verifyPublicKey(publicKey, pubFormat, expectedPubBytes)
                        }
                    }
                }

                put(keyReference, publicKeys to privateKeys)
            }
        }
    }

    private suspend fun AlgorithmTestScope<DSA>.getPublicKey(privateKey: DSA.PrivateKey): DSA.PublicKey? = try {
        privateKey.getPublicKey()
    } catch (cause: Throwable) {
        if (!supportsPublicKeyAccess(cause)) null
        else throw cause
    }
}
