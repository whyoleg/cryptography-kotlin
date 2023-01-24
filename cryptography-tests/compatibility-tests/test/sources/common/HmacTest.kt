package dev.whyoleg.cryptography.tests.compatibility

import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.test.utils.*
import dev.whyoleg.cryptography.tests.compatibility.api.*
import kotlinx.serialization.*
import kotlin.test.*

private const val keyIterations = 10
private const val dataIterations = 10
private const val maxDataSize = 10000

class HmacTest : CompatibilityTest<HMAC>(HMAC) {

    @Serializable
    private data class KeyParameters(val digest: String) : TestParameters

    override suspend fun CompatibilityTestContext<HMAC>.generate() {
        val signatureParametersId = api.signatures.saveParameters(TestParameters.Empty)
        generateDigests { digest, _ ->
            val keyParametersId = api.keys.saveParameters(KeyParameters(digest.name))
            algorithm.keyGenerator(digest).generateKeys(keyIterations) { key ->
                val keyReference = api.keys.saveData(keyParametersId, KeyData {
                    put(StringKeyFormat.RAW, key.encodeTo(HMAC.Key.Format.RAW))
                    if (supportsJwk()) put(StringKeyFormat.JWK, key.encodeTo(HMAC.Key.Format.JWK))
                })

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

    override suspend fun CompatibilityTestContext<HMAC>.validate() {
        val keys = buildMap {
            api.keys.getParameters<KeyParameters> { (digestName), parametersId ->
                val keyDecoder = algorithm.keyDecoder(digest(digestName))
                api.keys.getData<KeyData>(parametersId) { (formats), keyReference ->
                    val keys = keyDecoder.decodeFrom(formats) { stringFormat ->
                        when (stringFormat) {
                            StringKeyFormat.RAW -> HMAC.Key.Format.RAW
                            StringKeyFormat.JWK -> HMAC.Key.Format.JWK.takeIf { supportsJwk() }
                            else                -> error("Unsupported key format: $stringFormat")
                        }
                    }
                    keys.forEach { key ->
                        formats[StringKeyFormat.RAW]?.let { bytes ->
                            assertContentEquals(bytes, key.encodeTo(HMAC.Key.Format.RAW), "Key RAW encoding")
                        }
                    }
                    put(keyReference, keys)
                }
            }
        }
        api.signatures.getParameters<TestParameters.Empty> { _, parametersId ->
            api.signatures.getData<SignatureData>(parametersId) { (keyReference, data, signature), _ ->
                keys.getValue(keyReference).forEach { key ->
                    val verifier = key.signatureVerifier()
                    val generator = key.signatureGenerator()

                    assertTrue(verifier.verifySignature(data, signature), "Verify")
                    assertTrue(verifier.verifySignature(data, generator.generateSignature(data)), "Sign-Verify")
                }
            }
        }
    }
}
