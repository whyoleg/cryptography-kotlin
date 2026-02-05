/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.compatibility

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import dev.whyoleg.cryptography.providers.tests.compatibility.api.*
import dev.whyoleg.cryptography.random.*
import kotlinx.io.bytestring.*
import kotlinx.serialization.*

private const val maxDataSize = 10000

abstract class HmacCompatibilityTest(provider: CryptographyProvider) : CompatibilityTest<HMAC>(HMAC, provider) {

    @Serializable
    private data class KeyParameters(val digestName: String) : TestParameters {
        val digest get() = digest(digestName)
    }

    override suspend fun CompatibilityTestScope<HMAC>.generate(isStressTest: Boolean) {
        val keyIterations = when {
            isStressTest -> 10
            else         -> 5
        }
        val dataIterations = when {
            isStressTest -> 10
            else         -> 5
        }

        val signatureParametersId = api.signatures.saveParameters(TestParameters.Empty)
        DigestsForCompatibility.forEach { digest ->
            if (!supportsDigest(digest)) return@forEach

            val keyParametersId = api.keys.saveParameters(KeyParameters(digest.name))
            algorithm.keyGenerator(digest).generateKeys(keyIterations) { key ->
                val keyReference = api.keys.saveData(
                    keyParametersId,
                    KeyData(key.encodeTo(HMAC.Key.Format.entries, ::supportsFormat))
                )

                val signatureGenerator = key.signatureGenerator()
                val signatureVerifier = key.signatureVerifier()
                repeat(dataIterations) {
                    val dataSize = CryptographyRandom.nextInt(maxDataSize)
                    logger.log { "data.size      = $dataSize" }
                    val data = ByteString(CryptographyRandom.nextBytes(dataSize))
                    val signature = signatureGenerator.generateSignature(data)
                    logger.log { "signature.size = ${signature.size}" }

                    signatureVerifier.assertVerifySignature(data, signature, "Initial Verify")

                    api.signatures.saveData(signatureParametersId, SignatureData(keyReference, data, signature))
                }
            }
        }
    }

    override suspend fun CompatibilityTestScope<HMAC>.validate() {
        val keys = buildMap {
            api.keys.getParameters<KeyParameters> { parameters, parametersId, _ ->
                if (!supportsDigest(parameters.digest)) return@getParameters

                val keyDecoder = algorithm.keyDecoder(parameters.digest)
                api.keys.getData<KeyData>(parametersId) { (formats), keyReference, _ ->
                    val keys = keyDecoder.decodeFrom(
                        formats = formats,
                        formatOf = HMAC.Key.Format::valueOf,
                        supports = ::supportsFormat
                    ) { key, format, bytes ->
                        when (format) {
                            HMAC.Key.Format.RAW -> assertContentEquals(bytes, key.encodeToByteString(format), "Key $format encoding")
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

                    verifier.assertVerifySignature(data, signature, "Verify")
                    verifier.assertVerifySignature(data, generator.generateSignature(data), "Sign-Verify")
                }
            }
        }
    }
}
