/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.compatibility

import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.providers.tests.compatibility.api.*
import dev.whyoleg.cryptography.providers.tests.support.*
import dev.whyoleg.cryptography.random.*
import kotlinx.serialization.*
import kotlin.test.*

private const val keyIterations = 5
private const val dataIterations = 5
private const val maxDataSize = 10000

class HmacTest : CompatibilityTest<HMAC>(HMAC) {

    @Serializable
    private data class KeyParameters(val digest: String) : TestParameters

    override suspend fun CompatibilityTestScope<HMAC>.generate() {
        val signatureParametersId = api.signatures.saveParameters(TestParameters.Empty)
        generateDigests { digest, _ ->
            val keyParametersId = api.keys.saveParameters(KeyParameters(digest.name))
            algorithm.keyGenerator(digest).generateKeys(keyIterations) { key ->
                val keyReference = api.keys.saveData(
                    keyParametersId,
                    KeyData(key.encodeTo(HMAC.Key.Format.entries, ::supportsKeyFormat))
                )

                val signatureGenerator = key.signatureGenerator()
                val signatureVerifier = key.signatureVerifier()
                repeat(dataIterations) {
                    val dataSize = CryptographyRandom.nextInt(maxDataSize)
                    logger.log { "data.size      = $dataSize" }
                    val data = CryptographyRandom.nextBytes(dataSize)
                    val signature = signatureGenerator.generateSignature(data)
                    logger.log { "signature.size = ${signature.size}" }

                    assertTrue(signatureVerifier.verifySignature(data, signature), "Initial Verify")

                    api.signatures.saveData(signatureParametersId, SignatureData(keyReference, data, signature))
                }
            }
        }
    }

    override suspend fun CompatibilityTestScope<HMAC>.validate() {
        val keys = buildMap {
            api.keys.getParameters<KeyParameters> { (digestName), parametersId, _ ->
                val keyDecoder = algorithm.keyDecoder(digest(digestName))
                api.keys.getData<KeyData>(parametersId) { (formats), keyReference, _ ->
                    val keys = keyDecoder.decodeFrom(
                        formats = formats,
                        formatOf = HMAC.Key.Format::valueOf,
                        supports = ::supportsKeyFormat
                    ) { key, format, bytes ->
                        when (format) {
                            HMAC.Key.Format.RAW -> assertContentEquals(bytes, key.encodeTo(format), "Key $format encoding")
                            HMAC.Key.Format.JWK -> {} //no check for JWK yet
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

                    assertTrue(verifier.verifySignature(data, signature), "Verify")
                    assertTrue(verifier.verifySignature(data, generator.generateSignature(data)), "Sign-Verify")
                }
            }
        }
    }
}
