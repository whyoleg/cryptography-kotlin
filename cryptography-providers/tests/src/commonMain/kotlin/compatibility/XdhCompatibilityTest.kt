/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.compatibility

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import dev.whyoleg.cryptography.providers.tests.compatibility.api.*
import dev.whyoleg.cryptography.serialization.pem.*
import kotlinx.io.bytestring.*
import kotlinx.serialization.*
import kotlin.test.*

private val publicKeyFormats = listOf(
    XDH.PublicKey.Format.JWK,
    XDH.PublicKey.Format.RAW,
    XDH.PublicKey.Format.DER,
    XDH.PublicKey.Format.PEM,
).associateBy { it.name }

private val privateKeyFormats = listOf(
    XDH.PrivateKey.Format.JWK,
    XDH.PrivateKey.Format.RAW,
    XDH.PrivateKey.Format.DER,
    XDH.PrivateKey.Format.PEM,
).associateBy { it.name }

abstract class XdhCompatibilityTest(
    provider: CryptographyProvider,
) : CompatibilityTest<XDH>(XDH, provider) {

    @Serializable
    private data class KeyParameters(val curveName: String) : TestParameters {
        val curve get() = XDH.Curve.valueOf(curveName)
    }

    override suspend fun CompatibilityTestScope<XDH>.generate(isStressTest: Boolean) {
        val parametersId = api.sharedSecrets.saveParameters(TestParameters.Empty)
        XDH.Curve.entries.forEach { curve ->
            if (!supportsCurve(curve)) return@forEach

            val keyParametersId = api.keyPairs.saveParameters(KeyParameters(curve.name))
            generateKeys(
                curve = curve,
                keyParametersId = keyParametersId,
                isStressTest = isStressTest
            ) { keyPair, keyReference ->

                generateKeys(
                    curve = curve,
                    keyParametersId = keyParametersId,
                    isStressTest = isStressTest
                ) { otherKeyPair, otherKeyReference ->

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

    override suspend fun CompatibilityTestScope<XDH>.validate() {
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

    private suspend fun CompatibilityTestScope<XDH>.generateKeys(
        curve: XDH.Curve,
        keyParametersId: TestParametersId,
        isStressTest: Boolean,
        block: suspend (keyPair: XDH.KeyPair, keyReference: TestReference) -> Unit,
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
        publicKey: XDH.PublicKey,
        format: XDH.PublicKey.Format,
        expected: ByteString,
    ) {
        when (format) {
            XDH.PublicKey.Format.JWK -> {}
            XDH.PublicKey.Format.RAW,
            XDH.PublicKey.Format.DER,
                                     -> {
                assertContentEquals(expected, publicKey.encodeToByteString(format), "Public Key $format encoding")
            }
            XDH.PublicKey.Format.PEM -> {
                val expected = PemDocument.decode(expected)
                val actual = PemDocument.decode(publicKey.encodeToByteString(format))

                assertEquals(expected.label, actual.label)
                assertEquals(PemLabel.PublicKey, actual.label)
                assertContentEquals(expected.content, actual.content, "Public Key $format content encoding")
            }
        }
    }

    protected suspend fun CompatibilityTestScope<XDH>.validateKeys() = buildMap {
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
                        XDH.PrivateKey.Format.JWK -> {}
                        XDH.PrivateKey.Format.RAW -> {
                            assertContentEquals(byteString, key.encodeToByteString(format))
                        }
                        XDH.PrivateKey.Format.DER -> {
                            assertPrivateKeyInfoEquals(byteString, key.encodeToByteString(format))
                        }
                        XDH.PrivateKey.Format.PEM -> {
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

    private suspend fun AlgorithmTestScope<XDH>.getPublicKey(privateKey: XDH.PrivateKey): XDH.PublicKey? = try {
        privateKey.getPublicKey()
    } catch (cause: Throwable) {
        if (!supportsPublicKeyAccess(cause)) null
        else throw cause
    }
}
