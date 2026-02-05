/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.compatibility

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import dev.whyoleg.cryptography.providers.tests.compatibility.api.*
import dev.whyoleg.cryptography.serialization.asn1.*
import dev.whyoleg.cryptography.serialization.asn1.modules.*
import dev.whyoleg.cryptography.serialization.pem.*
import kotlinx.io.bytestring.*
import kotlinx.serialization.*
import kotlin.test.*

private val publicKeyFormats = listOf(
    EC.PublicKey.Format.JWK,
    EC.PublicKey.Format.RAW,
    EC.PublicKey.Format.RAW.Compressed,
    EC.PublicKey.Format.DER,
    EC.PublicKey.Format.PEM,
).associateBy { it.name }

private val privateKeyFormats = listOf(
    EC.PrivateKey.Format.JWK,
    EC.PrivateKey.Format.RAW,
    EC.PrivateKey.Format.DER,
    EC.PrivateKey.Format.PEM,
    EC.PrivateKey.Format.DER.SEC1,
    EC.PrivateKey.Format.PEM.SEC1,
).associateBy { it.name }

val EcCurves = listOf(
    EC.Curve.P256, EC.Curve.P384, EC.Curve.P521,
    EC.Curve.secp256k1,
    EC.Curve.brainpoolP256r1, EC.Curve.brainpoolP384r1, EC.Curve.brainpoolP512r1,
)

abstract class EcCompatibilityTest<PublicK : EC.PublicKey, PrivateK : EC.PrivateKey<PublicK>, KP : EC.KeyPair<PublicK, PrivateK>, A : EC<PublicK, PrivateK, KP>>(
    algorithmId: CryptographyAlgorithmId<A>,
    provider: CryptographyProvider,
) : CompatibilityTest<A>(algorithmId, provider) {
    @Serializable
    protected data class KeyParameters(val curveName: String) : TestParameters {
        val curve get() = EC.Curve(curveName)
    }

    protected suspend fun CompatibilityTestScope<A>.generateKeys(
        curve: EC.Curve,
        keyParametersId: TestParametersId,
        isStressTest: Boolean,
        block: suspend (keyPair: KP, keyReference: TestReference, keyParameters: KeyParameters) -> Unit,
    ) {
        val keyIterations = when {
            isStressTest -> 5
            else         -> 2
        }

        algorithm.keyPairGenerator(curve).generateKeys(keyIterations) { keyPair ->
            val publicKeyData = KeyData(keyPair.publicKey.encodeTo(publicKeyFormats.values, ::supportsFormat))
            val privateKeyData = KeyData(keyPair.privateKey.encodeTo(privateKeyFormats.values, ::supportsFormat))

            assertEquals(
                publicKeyData.formats,
                keyPair.privateKey.getPublicKey().encodeTo(publicKeyFormats.values, ::supportsFormat),
            )

            val keyReference = api.keyPairs.saveData(keyParametersId, KeyPairData(publicKeyData, privateKeyData))

            block(keyPair, keyReference, KeyParameters(curve.name))
        }
    }

    private suspend fun verifyPublicKey(
        publicKey: PublicK,
        format: EC.PublicKey.Format,
        expected: ByteString,
    ) {
        when (format) {
            EC.PublicKey.Format.JWK -> {}
            EC.PublicKey.Format.RAW,
            EC.PublicKey.Format.RAW.Compressed,
            EC.PublicKey.Format.DER,
                                    -> {
                assertContentEquals(expected, publicKey.encodeToByteString(format), "Public Key $format encoding")
            }
            EC.PublicKey.Format.PEM -> {
                val expected = PemDocument.decode(expected)
                val actual = PemDocument.decode(publicKey.encodeToByteString(format))

                assertEquals(expected.label, actual.label)
                assertEquals(PemLabel.PublicKey, actual.label)
                assertContentEquals(expected.content, actual.content, "Public Key $format content encoding")
            }
        }
    }

    protected suspend fun CompatibilityTestScope<A>.validateKeys() = buildMap {
        api.keyPairs.getParameters<KeyParameters> { keyParameters, parametersId, _ ->
            if (!supportsCurve(keyParameters.curve)) return@getParameters

            val privateKeyDecoder = algorithm.privateKeyDecoder(keyParameters.curve)
            val publicKeyDecoder = algorithm.publicKeyDecoder(keyParameters.curve)

            api.keyPairs.getData<KeyPairData>(parametersId) { (public, private), keyReference, otherContext ->
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
                    supportsDecoding = { f, b -> supportsPrivateKeyDecoding(f, b, otherContext) }
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
                        EC.PrivateKey.Format.JWK -> {}
                        EC.PrivateKey.Format.RAW -> {
                            assertContentEquals(byteString, key.encodeToByteString(format))
                        }
                        EC.PrivateKey.Format.DER.SEC1 -> {
                            assertEcPrivateKeyEquals(byteString.toByteArray(), key.encodeToByteArray(format))
                        }
                        EC.PrivateKey.Format.PEM.SEC1 -> {
                            val expected = PemDocument.decode(byteString)
                            val actual = PemDocument.decode(key.encodeToByteString(format))

                            assertEquals(PemLabel.EcPrivateKey, actual.label)
                            assertEquals(expected.label, actual.label)

                            assertEcPrivateKeyEquals(expected.content.toByteArray(), actual.content.toByteArray())
                        }
                        EC.PrivateKey.Format.DER -> {
                            assertPkcs8EcPrivateKeyEquals(byteString.toByteArray(), key.encodeToByteArray(format))
                        }
                        EC.PrivateKey.Format.PEM -> {
                            val expected = PemDocument.decode(byteString)
                            val actual = PemDocument.decode(key.encodeToByteString(format))

                            assertEquals(expected.label, actual.label)
                            assertEquals(PemLabel.PrivateKey, actual.label)

                            assertPkcs8EcPrivateKeyEquals(expected.content.toByteArray(), actual.content.toByteArray())
                        }
                    }
                }
                put(keyReference, publicKeys to privateKeys)
            }
        }
    }

    protected suspend fun <PublicK : EC.PublicKey> AlgorithmTestScope<out EC<*, *, *>>.getPublicKey(
        privateKey: EC.PrivateKey<PublicK>,
    ): PublicK? = try {
        privateKey.getPublicKey()
    } catch (cause: Throwable) {
        if (!supportsPublicKeyAccess(cause)) null
        else throw cause
    }
}

private fun assertEcPrivateKeyEquals(
    expectedBytes: ByteArray,
    actualBytes: ByteArray,
    requireParametersCheck: Boolean = true,
) {
    val expected = Der.decodeFromByteArray(EcPrivateKey.serializer(), expectedBytes)
    val actual = Der.decodeFromByteArray(EcPrivateKey.serializer(), actualBytes)

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
    val expected = Der.decodeFromByteArray(PrivateKeyInfo.serializer(), expectedBytes)
    val actual = Der.decodeFromByteArray(PrivateKeyInfo.serializer(), actualBytes)

    assertEquals(expected.version, actual.version, "PrivateKeyInfo.version")
    val expectedAlgorithm = assertIs<EcAlgorithmIdentifier>(expected.privateKeyAlgorithm)
    val actualAlgorithm = assertIs<EcAlgorithmIdentifier>(actual.privateKeyAlgorithm)
    assertEquals(expectedAlgorithm.parameters, actualAlgorithm.parameters, "PrivateKeyInfo.parameters")

    assertEcPrivateKeyEquals(
        expectedBytes = expected.privateKey,
        actualBytes = actual.privateKey,
        // different providers could encode or not encode parameters inside
        requireParametersCheck = false
    )
}
