/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.algorithms.asymmetric

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.providers.tests.api.compatibility.*
import dev.whyoleg.cryptography.random.*
import kotlinx.io.bytestring.*
import kotlin.test.*

private const val maxDataSize = 10000

abstract class RsaPkcs1CompatibilityTest(provider: CryptographyProvider) :
    RsaBasedCompatibilityTest<RSA.PKCS1.PublicKey, RSA.PKCS1.PrivateKey, RSA.PKCS1.KeyPair, RSA.PKCS1>(RSA.PKCS1, provider) {

    override suspend fun CompatibilityTestScope<RSA.PKCS1>.generate(isStressTest: Boolean) {
        val signatureIterations = when {
            isStressTest -> 5
            else         -> 2
        }
        val signatureParametersId = api.signatures.saveParameters(TestParameters.Empty)
        generateKeys(isStressTest) { keyPair, keyReference, _ ->
            val signer = keyPair.privateKey.signatureGenerator()
            val verifier = keyPair.publicKey.signatureVerifier()

            repeat(signatureIterations) {
                val dataSize = CryptographyRandom.nextInt(maxDataSize)
                logger.log { "data.size      = $dataSize" }
                val data = ByteString(CryptographyRandom.nextBytes(dataSize))
                val signature = signer.generateSignature(data)
                logger.log { "signature.size = ${signature.size}" }

                assertTrue(verifier.verifySignature(data, signature), "Initial Verify")

                api.signatures.saveData(signatureParametersId, SignatureData(keyReference, data, signature))
            }
        }
    }

    override suspend fun CompatibilityTestScope<RSA.PKCS1>.validate() {
        val keyPairs = validateKeys()

        api.signatures.getParameters<TestParameters.Empty> { _, parametersId, _ ->
            api.signatures.getData<SignatureData>(parametersId) { (keyReference, data, signature), _, _ ->
                val (publicKeys, privateKeys) = keyPairs[keyReference] ?: return@getData
                val verifiers = publicKeys.map { it.signatureVerifier() }
                val generators = privateKeys.map { it.signatureGenerator() }

                verifiers.forEach { verifier ->
                    assertTrue(verifier.verifySignature(data, signature), "Verify")

                    generators.forEach { generator ->
                        assertTrue(verifier.verifySignature(data, generator.generateSignature(data)), "Sign-Verify")
                    }
                }
            }
        }
    }
}
