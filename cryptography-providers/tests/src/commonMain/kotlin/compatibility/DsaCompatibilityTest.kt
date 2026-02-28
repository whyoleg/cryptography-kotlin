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

abstract class DsaCompatibilityTest(
    provider: CryptographyProvider,
) : CompatibilityTest<DSA>(DSA, provider) {

    @Serializable
    private data class KeyParameters(
        val keySizeBits: Int,
    ) : TestParameters

    @Serializable
    private data class SignatureParameters(
        val digestName: String,
        val keySizeBits: Int,
        val signatureFormat: DSA.SignatureFormat = DSA.SignatureFormat.DER,
    ) : TestParameters {
        val digest: CryptographyAlgorithmId<Digest> get() = digest(digestName)
    }

    private val publicKeyFormats = linkedMapOf(
        "DER" to DSA.PublicKey.Format.DER,
        "PEM" to DSA.PublicKey.Format.PEM,
        "JWK" to DSA.PublicKey.Format.JWK,
    )

    private val privateKeyFormats = linkedMapOf(
        "DER" to DSA.PrivateKey.Format.DER,
        "PEM" to DSA.PrivateKey.Format.PEM,
        "JWK" to DSA.PrivateKey.Format.JWK,
    )

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
            DSA.PublicKey.Format.JWK -> {
                // We treat JWK as a stable, canonical encoding in this library.
                // If a provider doesn't guarantee canonical JWK, it should not report support for it.
                assertContentEquals(expected, publicKey.encodeToByteString(format))
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
            DSA.PrivateKey.Format.JWK -> {
                assertContentEquals(expected, privateKey.encodeToByteString(format))
            }
        }
    }

    override suspend fun CompatibilityTestScope<DSA>.generate(isStressTest: Boolean) {
        val keyIterations = if (isStressTest) 5 else 2
        val signatureIterations = if (isStressTest) 5 else 2

        val cases = listOf(
            SHA1 to 1024,
            SHA256 to 2048,
        )

        cases.forEach { (digest, keySizeBits) ->
            if (!supportsDigest(digest)) return@forEach

            val sigParams = SignatureParameters(digestName = digest.name, keySizeBits = keySizeBits)
            val signatureParametersId = api.signatures.saveParameters(sigParams)

            val keyParamsId = api.keyPairs.saveParameters(KeyParameters(keySizeBits))
            val generator = algorithm.keyPairGenerator(keySizeBits.bits)

            generator.generateKeys(keyIterations) { keyPair ->
                val publicKeyData = KeyData(keyPair.publicKey.encodeTo(publicKeyFormats.values, ::supportsFormat))
                val privateKeyData = KeyData(keyPair.privateKey.encodeTo(privateKeyFormats.values, ::supportsFormat))
                val keyReference = api.keyPairs.saveData(keyParamsId, KeyPairData(publicKeyData, privateKeyData))

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

    override suspend fun CompatibilityTestScope<DSA>.validate() {
        val keyPairs = validateKeys()

        api.signatures.getParameters<SignatureParameters> { sigParams, parametersId, _ ->
            if (!supportsDigest(sigParams.digest)) return@getParameters

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

    private suspend fun CompatibilityTestScope<DSA>.validateKeys():
        Map<TestReference, Pair<List<DSA.PublicKey>, List<DSA.PrivateKey>>> = buildMap {

        api.keyPairs.getParameters<KeyParameters> { _, parametersId, _ ->
            val pubDecoder = algorithm.publicKeyDecoder()
            val privDecoder = algorithm.privateKeyDecoder()

            api.keyPairs.getData<KeyPairData>(parametersId) { (public, private), keyReference, _ ->
                val publicKeys = pubDecoder.decodeFrom(
                    formats = public.formats,
                    formatOf = publicKeyFormats::getValue,
                    supports = ::supportsFormat,
                    validate = ::verifyPublicKey
                )

                val privateKeys = privDecoder.decodeFrom(
                    formats = private.formats,
                    formatOf = privateKeyFormats::getValue,
                    supports = ::supportsFormat,
                    validate = { key, format, bytes ->
                        verifyPrivateKey(key, format, bytes)

                        // Optional: derived public key should match stored encodings (if supported)
                        runCatching { key.getPublicKey() }.getOrNull()?.let { derived ->
                            public.formats.filterSupportedFormats(
                                formatOf = publicKeyFormats::getValue,
                                supports = ::supportsFormat,
                            ).forEach { (pubFormat, expectedPubBytes) ->
                                verifyPublicKey(derived, pubFormat, expectedPubBytes)
                            }
                        }
                    }
                )

                put(keyReference, publicKeys to privateKeys)
            }
        }
    }
}
