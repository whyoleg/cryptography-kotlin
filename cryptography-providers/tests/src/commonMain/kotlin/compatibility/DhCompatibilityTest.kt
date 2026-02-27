/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.compatibility

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.providers.tests.*
import dev.whyoleg.cryptography.providers.tests.compatibility.api.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.pem.*
import kotlinx.io.bytestring.*
import kotlinx.serialization.*
import kotlin.test.*

private val parametersFormats = listOf(
    DH.Parameters.Format.DER,
    DH.Parameters.Format.PEM,
).associateBy { it.name }

private val publicKeyFormats = listOf(
    DH.PublicKey.Format.DER,
    DH.PublicKey.Format.PEM,
).associateBy { it.name }

private val privateKeyFormats = listOf(
    DH.PrivateKey.Format.DER,
    DH.PrivateKey.Format.PEM,
).associateBy { it.name }

abstract class DhCompatibilityTest(
    provider: CryptographyProvider,
) : CompatibilityTest<DH>(DH, provider) {

    @Serializable
    private data class DhKeyParameters(
        val parameters: KeyData,
    ) : TestParameters

    override suspend fun CompatibilityTestScope<DH>.generate(isStressTest: Boolean) {
        val parametersId = api.sharedSecrets.saveParameters(TestParameters.Empty)

        val parameterIterations = when {
            isStressTest -> 5
            else         -> 2
        }

        val dhParameters = buildList {
            if (supportsParameterGeneration()) {
                listOf(1024, 2048).forEach { primeSize ->
                    listOf(null, 256, 512).forEach { privateValueSize ->
                        val generator = algorithm.parametersGenerator(primeSize.bits, privateValueSize?.bits)
                        repeat(parameterIterations) {
                            add(generator.generateParameters())
                        }
                    }
                }
            }

            val rfcPrimeHex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
                    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
                    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
                    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
                    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
                    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
                    "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
                    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
                    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
                    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
                    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"

            add(
                algorithm.parametersDecoder().decodeFromByteArray(
                    DH.Parameters.Format.DER, Der.encodeToByteArray(
                        DhParameters(
                            prime = BigInt.fromMagnitude(sign = 1, rfcPrimeHex.hexToByteArray()),
                            base = 2.toBigInt(),
                        )
                    )
                )
            )
        }

        dhParameters.forEach { parameters ->
            // TODO: store initial parameters too?
            val keyParametersId = api.keyPairs.saveParameters(
                DhKeyParameters(KeyData(parameters.encodeTo(parametersFormats.values, ::supportsFormat)))
            )

            generateKeys(parameters, keyParametersId, isStressTest) { keyPair, keyReference ->
                generateKeys(parameters, keyParametersId, isStressTest) { otherKeyPair, otherKeyReference ->
                    val secrets = listOf(
                        keyPair.privateKey.sharedSecretGenerator().generateSharedSecret(otherKeyPair.publicKey),
                        keyPair.publicKey.sharedSecretGenerator().generateSharedSecret(otherKeyPair.privateKey),
                        otherKeyPair.privateKey.sharedSecretGenerator().generateSharedSecret(keyPair.publicKey),
                        otherKeyPair.publicKey.sharedSecretGenerator().generateSharedSecret(keyPair.privateKey),
                    )

                    repeat(secrets.size) { i ->
                        repeat(secrets.size) { j ->
                            if (j > i) assertContentEquals(secrets[i], secrets[j], "Initial $i + $j")
                        }
                    }

                    api.sharedSecrets.saveData(
                        parametersId = parametersId,
                        data = SharedSecretData(
                            keyReference = keyReference,
                            otherKeyReference = otherKeyReference,
                            sharedSecret = secrets.first()
                        )
                    )
                }
            }
        }
    }

    private suspend fun CompatibilityTestScope<DH>.generateKeys(
        parameters: DH.Parameters,
        keyParametersId: TestParametersId,
        isStressTest: Boolean,
        block: suspend (keyPair: DH.KeyPair, keyReference: TestReference) -> Unit,
    ) {
        val keyIterations = when {
            isStressTest -> 5
            else         -> 2
        }

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

    override suspend fun CompatibilityTestScope<DH>.validate() {
        val keyPairs = validateKeys()

        api.sharedSecrets.getParameters<TestParameters.Empty> { _, parametersId, _ ->
            api.sharedSecrets.getData<SharedSecretData>(parametersId) { (keyReference, otherKeyReference, sharedSecret), _, _ ->
                val (publicKeys, privateKeys) = keyPairs[keyReference] ?: return@getData
                val (otherPublicKeys, otherPrivateKeys) = keyPairs[otherKeyReference] ?: return@getData

                publicKeys.forEach { publicKey ->
                    otherPrivateKeys.forEach { otherPrivateKey ->
                        assertContentEquals(
                            sharedSecret,
                            publicKey.sharedSecretGenerator().generateSharedSecret(otherPrivateKey),
                            "Public + Other Private"
                        )
                        assertContentEquals(
                            sharedSecret,
                            otherPrivateKey.sharedSecretGenerator().generateSharedSecret(publicKey),
                            "Other Private + Public"
                        )
                    }
                }
                privateKeys.forEach { privateKey ->
                    otherPublicKeys.forEach { otherPublicKey ->
                        assertContentEquals(
                            sharedSecret,
                            otherPublicKey.sharedSecretGenerator().generateSharedSecret(privateKey),
                            "Other Public + Private"
                        )
                        assertContentEquals(
                            sharedSecret,
                            privateKey.sharedSecretGenerator().generateSharedSecret(otherPublicKey),
                            "Private + Other Public"
                        )
                    }
                }
            }
        }
    }

    private suspend fun verifyParameters(
        parameters: DH.Parameters,
        format: DH.Parameters.Format,
        expected: ByteString,
    ) {
        when (format) {
            DH.Parameters.Format.DER -> {
                assertDhParametersEquals(expected, parameters.encodeToByteString(format))
            }
            DH.Parameters.Format.PEM -> {
                val expected = PemDocument.decode(expected)
                val actual = PemDocument.decode(parameters.encodeToByteString(format))

                assertEquals(expected.label, actual.label)
                assertEquals(PemLabel.DhParameters, actual.label)
                assertDhParametersEquals(expected.content, actual.content)
            }
        }
    }

    private suspend fun verifyPublicKey(
        publicKey: DH.PublicKey,
        format: DH.PublicKey.Format,
        expected: ByteString,
    ) {
        when (format) {
            DH.PublicKey.Format.DER -> {
                assertDhSubjectPublicKeyInfoEquals(expected, publicKey.encodeToByteString(format))
            }
            DH.PublicKey.Format.PEM -> {
                val expected = PemDocument.decode(expected)
                val actual = PemDocument.decode(publicKey.encodeToByteString(format))

                assertEquals(expected.label, actual.label)
                assertEquals(PemLabel.PublicKey, actual.label)
                assertDhSubjectPublicKeyInfoEquals(expected.content, actual.content)
            }
        }
    }

    private suspend fun CompatibilityTestScope<DH>.validateKeys() = buildMap {
        api.keyPairs.getParameters<DhKeyParameters> { keyParameters, parametersId, _ ->
            val parametersDecoder = algorithm.parametersDecoder()
            keyParameters.parameters.formats.filterSupportedFormats(
                formatOf = parametersFormats::getValue,
                supports = ::supportsFormat,
            ).forEach { (format, bytes) ->
                val decoded = parametersDecoder.decodeFromByteString(format, bytes)
                verifyParameters(decoded, format, bytes)
            }

            val privateKeyDecoder = algorithm.privateKeyDecoder()
            val publicKeyDecoder = algorithm.publicKeyDecoder()

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

                    getPublicKey(key)?.let { publicKey ->
                        public.formats.filterSupportedFormats(
                            formatOf = publicKeyFormats::getValue,
                            supports = ::supportsFormat,
                        ).forEach { (format, bytes) ->
                            verifyPublicKey(publicKey, format, bytes)
                        }
                    }

                    when (format) {
                        DH.PrivateKey.Format.DER -> {
                            assertContentEquals(byteString, key.encodeToByteString(format))
                        }
                        DH.PrivateKey.Format.PEM -> {
                            val expected = PemDocument.decode(byteString)
                            val actual = PemDocument.decode(key.encodeToByteString(format))

                            assertEquals(expected.label, actual.label)
                            assertEquals(PemLabel.PrivateKey, actual.label)

                            assertContentEquals(expected.content, actual.content)
                        }
                    }
                }
                put(keyReference, publicKeys to privateKeys)
            }
        }
    }

    private suspend fun AlgorithmTestScope<DH>.getPublicKey(privateKey: DH.PrivateKey): DH.PublicKey? = try {
        privateKey.getPublicKey()
    } catch (cause: Throwable) {
        if (!supportsPublicKeyAccess(cause)) null
        else throw cause
    }
}

// DH parameters comparison ignoring the optional privateValueLength field,
// which may not be preserved by all providers (e.g., the JDK not always preserve it for public keys)
private fun assertDhParametersEquals(expectedBytes: ByteString, actualBytes: ByteString) {
    val expected = Der.decodeFromByteArray(DhParameters.serializer(), expectedBytes.toByteArray())
    val actual = Der.decodeFromByteArray(DhParameters.serializer(), actualBytes.toByteArray())
    assertDhParametersEquals(expected, actual)
}

private fun assertDhParametersEquals(expected: DhParameters?, actual: DhParameters?) {
    assertNotNull(expected, "DhParameters should not be null")
    assertNotNull(actual, "DhParameters should not be null")
    assertEquals(expected.prime, actual.prime, "DhParameters.prime")
    assertEquals(expected.base, actual.base, "DhParameters.base")
    if (expected.privateValueLength != null && actual.privateValueLength != null) {
        assertEquals(expected.privateValueLength, actual.privateValueLength, "DhParameters.privateValueLength")
    }
}

private fun assertDhSubjectPublicKeyInfoEquals(expectedBytes: ByteString, actualBytes: ByteString) {
    val expected = Der.decodeFromByteArray(SubjectPublicKeyInfo.serializer(), expectedBytes.toByteArray())
    val actual = Der.decodeFromByteArray(SubjectPublicKeyInfo.serializer(), actualBytes.toByteArray())

    val expectedAlgorithm = assertIs<DhAlgorithmIdentifier>(expected.algorithm)
    val actualAlgorithm = assertIs<DhAlgorithmIdentifier>(actual.algorithm)
    assertDhParametersEquals(expectedAlgorithm.parameters, actualAlgorithm.parameters)

    assertBitArrayEquals(expected.subjectPublicKey, actual.subjectPublicKey, "SubjectPublicKeyInfo.subjectPublicKey")
}
