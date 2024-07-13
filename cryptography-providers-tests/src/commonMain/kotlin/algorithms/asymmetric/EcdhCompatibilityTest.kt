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
                        keyPair.privateKey.sharedSecretDerivation().deriveSharedSecret(otherKeyPair.publicKey),
                        keyPair.publicKey.sharedSecretDerivation().deriveSharedSecret(otherKeyPair.privateKey),
                        otherKeyPair.privateKey.sharedSecretDerivation().deriveSharedSecret(keyPair.publicKey),
                        otherKeyPair.publicKey.sharedSecretDerivation().deriveSharedSecret(keyPair.privateKey),
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
                            publicKey.sharedSecretDerivation().deriveSharedSecret(otherPrivateKey),
                            "Public + Other Private"
                        )
                        assertContentEquals(
                            sharedSecret,
                            otherPrivateKey.sharedSecretDerivation().deriveSharedSecret(publicKey),
                            "Other Private + Public"
                        )
                    }
                }
                privateKeys.forEach { privateKey ->
                    otherPublicKeys.forEach { otherPublicKey ->
                        assertContentEquals(
                            sharedSecret,
                            otherPublicKey.sharedSecretDerivation().deriveSharedSecret(privateKey),
                            "Other Public + Private"
                        )
                        assertContentEquals(
                            sharedSecret,
                            privateKey.sharedSecretDerivation().deriveSharedSecret(otherPublicKey),
                            "Private + Other Public"
                        )
                    }
                }
            }
        }
    }
}
