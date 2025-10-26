/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.compatibility

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import dev.whyoleg.cryptography.providers.tests.compatibility.api.*
import kotlinx.serialization.*

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
    protected data class KeyParameters(val keySize: Int) : TestParameters

    override suspend fun CompatibilityTestScope<DH>.generate(isStressTest: Boolean) {
        val parametersId = api.sharedSecrets.saveParameters(TestParameters.Empty)
        generateKeySizes { keySize ->
            if (!supportsKeySize(keySize)) return@generateKeySizes

            val keyParametersId = api.keyPairs.saveParameters(KeyParameters(keySize))
            generateKeys(
                keySize = keySize,
                keyParametersId = keyParametersId,
                isStressTest = isStressTest
            ) { keyPair, keyReference, _ ->

                generateKeys(
                    keySize = keySize,
                    keyParametersId = keyParametersId,
                    isStressTest = isStressTest
                ) { otherKeyPair, otherKeyReference, _ ->

                    val secrets = listOf(
                        keyPair.privateKey.sharedSecretGenerator().generateSharedSecret(otherKeyPair.publicKey),
                        otherKeyPair.privateKey.sharedSecretGenerator().generateSharedSecret(keyPair.publicKey),
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

    override suspend fun CompatibilityTestScope<DH>.validate() {
        val keyPairs = validateKeys()

        api.sharedSecrets.getParameters<TestParameters.Empty> { _, parametersId, _ ->
            api.sharedSecrets.getData<SharedSecretData>(parametersId) { (keyReference, otherKeyReference, sharedSecret), _, _ ->
                val (publicKeys, privateKeys) = keyPairs[keyReference] ?: return@getData
                val (otherPublicKeys, otherPrivateKeys) = keyPairs[otherKeyReference] ?: return@getData

                privateKeys.forEach { privateKey ->
                    otherPublicKeys.forEach { otherPublicKey ->
                        assertContentEquals(
                            sharedSecret,
                            privateKey.sharedSecretGenerator().generateSharedSecret(otherPublicKey),
                            "Private + Other Public"
                        )
                    }
                }
                otherPrivateKeys.forEach { otherPrivateKey ->
                    publicKeys.forEach { publicKey ->
                        assertContentEquals(
                            sharedSecret,
                            otherPrivateKey.sharedSecretGenerator().generateSharedSecret(publicKey),
                            "Other Private + Public"
                        )
                    }
                }
            }
        }
    }

    private inline fun generateKeySizes(block: (keySize: Int) -> Unit) {
        generate(block, 2048, 3072)
    }

    private suspend fun generateKeys(
        keySize: Int,
        keyParametersId: TestParametersId,
        isStressTest: Boolean,
        block: suspend (keyPair: DH.KeyPair, keyReference: TestReference, keyParameters: KeyParameters) -> Unit
    ) {
        val keyIterations = when {
            isStressTest -> 3
            else         -> 2
        }

        val parameters = algorithm.parametersGenerator(keySize).generateKey()
        
        algorithm.keyPairGenerator(parameters).generateKeys(keyIterations) { keyPair ->
            val keyReference = api.keyPairs.saveData(
                keyParametersId,
                KeyPairData(
                    public = KeyData(keyPair.publicKey.encodeTo(publicKeyFormats.values, ::supportsKeyFormat)),
                    private = KeyData(keyPair.privateKey.encodeTo(privateKeyFormats.values, ::supportsKeyFormat))
                )
            )

            block(keyPair, keyReference, KeyParameters(keySize))
        }
    }

    private suspend fun CompatibilityTestScope<DH>.validateKeys() = buildMap {
        api.keyPairs.getParameters<KeyParameters> { keyParameters, parametersId, _ ->
            if (!supportsKeySize(keyParameters.keySize)) return@getParameters

            val parameters = algorithm.parametersGenerator(keyParameters.keySize).generateKey()
            val publicKeyDecoder = algorithm.publicKeyDecoder(parameters)
            val privateKeyDecoder = algorithm.privateKeyDecoder(parameters)

            api.keyPairs.getData<KeyPairData>(parametersId) { keyPairData, _, dataReference ->
                val publicKeys = keyPairData.public.formats.mapNotNull { (formatName, bytes) ->
                    val format = publicKeyFormats[formatName] ?: return@mapNotNull null
                    if (!supportsKeyFormat(format)) return@mapNotNull null

                    runCatching { publicKeyDecoder.decodeFromByteArray(format, bytes) }
                        .onFailure { logger.e("Failed to decode public key", it) }
                        .getOrNull()
                }

                val privateKeys = keyPairData.private.formats.mapNotNull { (formatName, bytes) ->
                    val format = privateKeyFormats[formatName] ?: return@mapNotNull null
                    if (!supportsKeyFormat(format)) return@mapNotNull null

                    runCatching { privateKeyDecoder.decodeFromByteArray(format, bytes) }
                        .onFailure { logger.e("Failed to decode private key", it) }
                        .getOrNull()
                }

                this[dataReference] = publicKeys to privateKeys
            }
        }
    }

    private fun supportsKeySize(keySize: Int): Boolean {
        return runCatching {
            algorithm.parametersGenerator(keySize).generateKeyBlocking()
        }.isSuccess
    }

    protected open fun supportsKeyFormat(format: DH.PublicKey.Format): Boolean = true
    protected open fun supportsKeyFormat(format: DH.PrivateKey.Format): Boolean = true
}