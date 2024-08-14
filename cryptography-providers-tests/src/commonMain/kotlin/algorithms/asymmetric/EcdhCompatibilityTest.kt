/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.algorithms.asymmetric

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.providers.tests.api.*
import dev.whyoleg.cryptography.providers.tests.api.compatibility.*
import kotlin.test.*

abstract class EcdhCompatibilityTest(
    provider: CryptographyProvider,
) : EcCompatibilityTest<ECDH.PublicKey, ECDH.PrivateKey, ECDH.KeyPair, ECDH>(ECDH, provider) {
    override suspend fun CompatibilityTestScope<ECDH>.generate(isStressTest: Boolean) {
        val parametersId = api.sharedSecrets.saveParameters(TestParameters.Empty)
        generateCurves { curve ->
            if (!supportsCurve(curve)) return@generateCurves

            val keyParametersId = api.keyPairs.saveParameters(KeyParameters(curve.name))
            generateKeys(
                curve = curve,
                keyParametersId = keyParametersId,
                isStressTest = isStressTest
            ) { keyPair, keyReference, _ ->

                generateKeys(
                    curve = curve,
                    keyParametersId = keyParametersId,
                    isStressTest = isStressTest
                ) { otherKeyPair, otherKeyReference, _ ->

                    val secrets = listOf(
                        keyPair.privateKey.sharedSecretGenerator().generateSharedSecret(otherKeyPair.publicKey),
                        keyPair.publicKey.sharedSecretGenerator().generateSharedSecret(otherKeyPair.privateKey),
                        otherKeyPair.privateKey.sharedSecretGenerator().generateSharedSecret(keyPair.publicKey),
                        otherKeyPair.publicKey.sharedSecretGenerator().generateSharedSecret(keyPair.privateKey),
                    )

                    repeat(secrets.size) { i ->
                        repeat(secrets.size) { j ->
                            if (j > i) assertContentEquals(secrets[i].toByteArray(), secrets[j].toByteArray(), "Initial $i + $j")
                        }
                    }

                    api.sharedSecrets.saveData(
                        parametersId = parametersId,
                        data = SharedSecretData(
                            keyReference = keyReference,
                            otherKeyReference = otherKeyReference,
                            sharedSecret = secrets.first().toByteArray()
                        )
                    )
                }
            }
        }
    }

    override suspend fun CompatibilityTestScope<ECDH>.validate() {
        val keyPairs = validateKeys()

        api.sharedSecrets.getParameters<TestParameters.Empty> { _, parametersId, _ ->
            api.sharedSecrets.getData<SharedSecretData>(parametersId) { (keyReference, otherKeyReference, sharedSecret), _, _ ->
                val (publicKeys, privateKeys) = keyPairs[keyReference] ?: return@getData
                val (otherPublicKeys, otherPrivateKeys) = keyPairs[otherKeyReference] ?: return@getData

                publicKeys.forEach { publicKey ->
                    otherPrivateKeys.forEach { otherPrivateKey ->
                        assertContentEquals(
                            sharedSecret,
                            publicKey.sharedSecretGenerator().generateSharedSecret(otherPrivateKey).toByteArray(),
                            "Public + Other Private"
                        )
                        assertContentEquals(
                            sharedSecret,
                            otherPrivateKey.sharedSecretGenerator().generateSharedSecret(publicKey).toByteArray(),
                            "Other Private + Public"
                        )
                    }
                }
                privateKeys.forEach { privateKey ->
                    otherPublicKeys.forEach { otherPublicKey ->
                        assertContentEquals(
                            sharedSecret,
                            otherPublicKey.sharedSecretGenerator().generateSharedSecret(privateKey).toByteArray(),
                            "Other Public + Private"
                        )
                        assertContentEquals(
                            sharedSecret,
                            privateKey.sharedSecretGenerator().generateSharedSecret(otherPublicKey).toByteArray(),
                            "Private + Other Public"
                        )
                    }
                }
            }
        }
    }
}
