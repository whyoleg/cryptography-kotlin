/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.compatibility

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import dev.whyoleg.cryptography.providers.tests.compatibility.api.*
import dev.whyoleg.cryptography.serialization.pem.*
import kotlinx.serialization.*
import kotlin.test.*

private val xdhPublicKeyFormats = listOf(
    XDH.PublicKey.Format.JWK,
    XDH.PublicKey.Format.RAW,
    XDH.PublicKey.Format.DER,
    XDH.PublicKey.Format.PEM,
).associateBy { it.name }

private val xdhPrivateKeyFormats = listOf(
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
        val curve get() = XDH.Curve(curveName)
    }

    override suspend fun CompatibilityTestScope<XDH>.generate(isStressTest: Boolean) {
        val parametersId = api.sharedSecrets.saveParameters(TestParameters.Empty)

        listOf(XDH.Curve.X25519, XDH.Curve.X448).forEach { curve ->
            val keyParametersId = api.keyPairs.saveParameters(KeyParameters(curve.name))

            val keyIterations = if (isStressTest) 5 else 2
            // Generate two key pairs for shared secret validation
            algorithm.keyPairGenerator(curve).generateKeys(keyIterations) { keyPair ->
                val keyReference = api.keyPairs.saveData(
                    keyParametersId,
                    KeyPairData(
                        public = KeyData(keyPair.publicKey.encodeTo(xdhPublicKeyFormats.values, ::supportsKeyFormat)),
                        private = KeyData(keyPair.privateKey.encodeTo(xdhPrivateKeyFormats.values, ::supportsKeyFormat))
                    )
                )

                algorithm.keyPairGenerator(curve).generateKeys(1) { otherKeyPair ->
                    val otherKeyReference = api.keyPairs.saveData(
                        keyParametersId,
                        KeyPairData(
                            public = KeyData(otherKeyPair.publicKey.encodeTo(xdhPublicKeyFormats.values, ::supportsKeyFormat)),
                            private = KeyData(otherKeyPair.privateKey.encodeTo(xdhPrivateKeyFormats.values, ::supportsKeyFormat))
                        )
                    )

                    val shared = keyPair.privateKey.sharedSecretGenerator().generateSharedSecret(otherKeyPair.publicKey)
                    api.sharedSecrets.saveData(parametersId, SharedSecretData(keyReference, otherKeyReference, shared))
                }
            }
        }
    }

    override suspend fun CompatibilityTestScope<XDH>.validate() {
        val keyPairs = buildMap {
            api.keyPairs.getParameters<KeyParameters> { params, parametersId, _ ->
                val publicKeyDecoder = algorithm.publicKeyDecoder(params.curve)
                val privateKeyDecoder = algorithm.privateKeyDecoder(params.curve)
                api.keyPairs.getData<KeyPairData>(parametersId) { (public, private), keyReference, _ ->
                    val publicKeys = publicKeyDecoder.decodeFrom(
                        formats = public.formats,
                        formatOf = xdhPublicKeyFormats::getValue,
                        supports = ::supportsKeyFormat
                    ) { key, format, bytes ->
                        when (format) {
                            XDH.PublicKey.Format.PEM -> {
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
                        formatOf = xdhPrivateKeyFormats::getValue,
                        supports = ::supportsKeyFormat
                    ) { key, format, bytes ->
                        when (format) {
                            XDH.PrivateKey.Format.PEM -> {
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

        api.sharedSecrets.getParameters<TestParameters.Empty> { _, parametersId, _ ->
            api.sharedSecrets.getData<SharedSecretData>(parametersId) { (keyReference, otherKeyReference, sharedSecret), _, _ ->
                val (publicKeys, privateKeys) = keyPairs[keyReference] ?: return@getData
                val (otherPublicKeys, otherPrivateKeys) = keyPairs[otherKeyReference] ?: return@getData

                // Verify both combinations generate the same secret
                publicKeys.forEach { publicKey ->
                    otherPrivateKeys.forEach { otherPrivateKey ->
                        assertContentEquals(sharedSecret, publicKey.sharedSecretGenerator().generateSharedSecret(otherPrivateKey))
                        assertContentEquals(sharedSecret, otherPrivateKey.sharedSecretGenerator().generateSharedSecret(publicKey))
                    }
                }
                privateKeys.forEach { privateKey ->
                    otherPublicKeys.forEach { otherPublicKey ->
                        assertContentEquals(sharedSecret, privateKey.sharedSecretGenerator().generateSharedSecret(otherPublicKey))
                        assertContentEquals(sharedSecret, otherPublicKey.sharedSecretGenerator().generateSharedSecret(privateKey))
                    }
                }
            }
        }
    }
}
