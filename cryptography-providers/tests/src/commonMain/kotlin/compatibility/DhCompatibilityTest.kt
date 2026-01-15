/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.compatibility

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.providers.tests.*
import dev.whyoleg.cryptography.providers.tests.compatibility.api.*
import kotlinx.serialization.*

// RFC 3526 MODP Group 14 (2048-bit) parameters for testing
private val testP = (
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
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
        ).hexToBigInt()

private val testG = 2.toBigInt()

@OptIn(ExperimentalStdlibApi::class)
private fun String.hexToBigInt(): BigInt {
    // Prepend 00 to ensure positive interpretation in two's complement
    val hex = "00" + (if (length % 2 == 0) this else "0$this")
    return hex.hexToByteArray().decodeToBigInt()
}

private val publicKeyFormats = listOf(
    DH.PublicKey.Format.RAW,
    DH.PublicKey.Format.DER,
    DH.PublicKey.Format.PEM,
).associateBy { it.name }

private val privateKeyFormats = listOf(
    DH.PrivateKey.Format.RAW,
    DH.PrivateKey.Format.DER,
    DH.PrivateKey.Format.PEM,
).associateBy { it.name }

abstract class DhCompatibilityTest(
    provider: CryptographyProvider,
) : CompatibilityTest<DH>(DH, provider) {

    @Serializable
    private data class DhKeyParameters(
        val pHex: String,
        val gHex: String,
    ) : TestParameters {
        fun toParameters() = DH.Parameters(pHex.hexToBigInt(), gHex.hexToBigInt())
    }

    private val testParameters = DH.Parameters(testP, testG)

    @OptIn(ExperimentalStdlibApi::class)
    private val testKeyParameters = DhKeyParameters(
        pHex = testP.encodeToByteArray().toHexString(),
        gHex = testG.encodeToByteArray().toHexString()
    )

    override suspend fun CompatibilityTestScope<DH>.generate(isStressTest: Boolean) {
        val parametersId = api.sharedSecrets.saveParameters(TestParameters.Empty)
        val keyParametersId = api.keyPairs.saveParameters(testKeyParameters)

        val keyIterations = when {
            isStressTest -> 5
            else         -> 2
        }

        repeat(keyIterations) {
            val keyPair = algorithm.keyPairGenerator(testParameters).generateKey()

            val publicKeyData = KeyData(keyPair.publicKey.encodeTo(publicKeyFormats.values, ::supportsKeyFormat))
            val privateKeyData = KeyData(keyPair.privateKey.encodeTo(privateKeyFormats.values, ::supportsKeyFormat))

            val keyReference = api.keyPairs.saveData(keyParametersId, KeyPairData(publicKeyData, privateKeyData))

            repeat(keyIterations) {
                val otherKeyPair = algorithm.keyPairGenerator(testParameters).generateKey()

                val otherPublicKeyData = KeyData(otherKeyPair.publicKey.encodeTo(publicKeyFormats.values, ::supportsKeyFormat))
                val otherPrivateKeyData = KeyData(otherKeyPair.privateKey.encodeTo(privateKeyFormats.values, ::supportsKeyFormat))

                val otherKeyReference = api.keyPairs.saveData(keyParametersId, KeyPairData(otherPublicKeyData, otherPrivateKeyData))

                // Generate shared secrets in all 4 combinations
                val secrets = listOf(
                    keyPair.privateKey.sharedSecretGenerator().generateSharedSecret(otherKeyPair.publicKey),
                    keyPair.publicKey.sharedSecretGenerator().generateSharedSecret(otherKeyPair.privateKey),
                    otherKeyPair.privateKey.sharedSecretGenerator().generateSharedSecret(keyPair.publicKey),
                    otherKeyPair.publicKey.sharedSecretGenerator().generateSharedSecret(keyPair.privateKey),
                )

                // Verify all 4 secrets are equal
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

    private suspend fun CompatibilityTestScope<DH>.validateKeys() = buildMap {
        api.keyPairs.getParameters<DhKeyParameters> { keyParameters, parametersId, _ ->
            val parameters = keyParameters.toParameters()
            val privateKeyDecoder = algorithm.privateKeyDecoder(parameters)
            val publicKeyDecoder = algorithm.publicKeyDecoder(parameters)

            api.keyPairs.getData<KeyPairData>(parametersId) { (public, private), keyReference, _ ->
                val publicKeys = publicKeyDecoder.decodeFrom(
                    formats = public.formats,
                    formatOf = publicKeyFormats::getValue,
                    supports = ::supportsKeyFormat,
                ) { _, _, _ -> } // no additional validation needed
                val privateKeys = privateKeyDecoder.decodeFrom(
                    formats = private.formats,
                    formatOf = privateKeyFormats::getValue,
                    supports = ::supportsKeyFormat,
                ) { _, _, _ -> } // no additional validation needed
                put(keyReference, publicKeys to privateKeys)
            }
        }
    }
}
