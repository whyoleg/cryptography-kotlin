/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.compatibility

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import dev.whyoleg.cryptography.providers.tests.compatibility.api.*
import dev.whyoleg.cryptography.random.*
import kotlinx.io.bytestring.*

private const val maxDataSize = 10000

abstract class Poly1305CompatibilityTest(provider: CryptographyProvider) :
    CompatibilityTest<Poly1305>(Poly1305, provider) {

    override suspend fun CompatibilityTestScope<Poly1305>.generate(isStressTest: Boolean) {
        val keyIterations = when {
            isStressTest -> 10
            else         -> 5
        }
        val dataIterations = when {
            isStressTest -> 10
            else         -> 5
        }

        val signatureParametersId = api.signatures.saveParameters(TestParameters.Empty)
        val keyParametersId = api.keys.saveParameters(TestParameters.Empty)
        algorithm.keyGenerator().generateKeys(keyIterations) { key ->
            val keyReference = api.keys.saveData(
                keyParametersId,
                KeyData(key.encodeTo(Poly1305.Key.Format.entries, ::supportsFormat))
            )

            val signer = key.signatureGenerator()
            val verifier = key.signatureVerifier()
            repeat(dataIterations) {
                val dataSize = CryptographyRandom.nextInt(maxDataSize)
                logger.log { "dataSize  = $dataSize" }

                val data = ByteString(CryptographyRandom.nextBytes(dataSize))
                val signature = signer.generateSignatureBlocking(data)
                logger.log { "signature.size = ${signature.size}" }

                verifier.assertVerifySignature(data, signature, "Initial Verify")
                api.signatures.saveData(signatureParametersId, SignatureData(keyReference, data, signature))
            }
        }
    }

    override suspend fun CompatibilityTestScope<Poly1305>.validate() {
        val keys = buildMap {
            api.keys.getParameters<TestParameters.Empty> { _, parametersId, _ ->
                api.keys.getData<KeyData>(parametersId) { (formats), keyReference, _ ->
                    val keys = algorithm.keyDecoder().decodeFrom(
                        formats = formats,
                        formatOf = Poly1305.Key.Format::valueOf,
                        supports = ::supportsFormat
                    ) { key, format, bytes ->
                        when (format) {
                            Poly1305.Key.Format.RAW -> assertContentEquals(
                                bytes,
                                key.encodeToByteString(format),
                                "Key $format encoding"
                            )
                        }
                    }
                    put(keyReference, keys)
                }
            }
        }
        api.signatures.getParameters<TestParameters.Empty> { _, parametersId, _ ->
            api.signatures.getData<SignatureData>(parametersId) { (keyReference, data, signature), _, _ ->
                keys[keyReference]?.forEach { key ->
                    val verifier = key.signatureVerifier()
                    val generator = key.signatureGenerator()
                    verifier.assertVerifySignature(data, signature, "Verify")
                    verifier.assertVerifySignature(data, generator.generateSignature(data), "Sign-Verify")
                }
            }
        }
    }
}
