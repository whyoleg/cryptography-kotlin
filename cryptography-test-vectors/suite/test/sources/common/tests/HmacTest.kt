package dev.whyoleg.cryptography.test.vectors.suite.tests

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.provider.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.test.support.*
import dev.whyoleg.cryptography.test.vectors.suite.*
import dev.whyoleg.cryptography.test.vectors.suite.api.*
import kotlinx.serialization.*

private const val keyIterations = 10
private const val dataIterations = 10
private const val maxDataSize = 10000

class HmacTest : TestVectorTest<HMAC>(HMAC) {

    @Serializable
    private data class KeyParameters(val digest: String) : TestVectorParameters

    private fun digest(name: String): CryptographyAlgorithmId<Digest> = when (name) {
        SHA1.name -> SHA1
        SHA256.name -> SHA256
        SHA384.name -> SHA384
        SHA512.name -> SHA512
        else -> error("Unknown digest: $name")
    }

    override suspend fun generate(logging: TestLoggingContext, api: TestVectorApi, provider: CryptographyProvider, algorithm: HMAC) {
        val signatureParametersId = api.signatures.saveParameters(TestVectorParameters.Empty)
        generateDigests { digest, _ ->
            val keyParametersId = api.keys.saveParameters(KeyParameters(digest.name))
            algorithm.keyGenerator(digest).generateKeys(keyIterations) { key ->
                val keyReference = api.keys.saveData(keyParametersId, KeyData {
                    put(StringKeyFormat.RAW, key.encodeTo(HMAC.Key.Format.RAW))
                    if (provider.supportsJwk) put(StringKeyFormat.JWK, key.encodeTo(HMAC.Key.Format.JWK))
                })

                val signatureGenerator = key.signatureGenerator()
                val signatureVerifier = key.signatureVerifier()
                repeat(dataIterations) {
                    val dataSize = CryptographyRandom.nextInt(maxDataSize)
                    logging.log("data.size      = $dataSize")
                    val data = CryptographyRandom.nextBytes(dataSize)
                    val signature = signatureGenerator.generateSignature(data)
                    logging.log("signature.size = ${signature.size}")

                    signatureVerifier.verifySignature(data, signature).assertTrue()

                    api.signatures.saveData(signatureParametersId, SignatureData(keyReference, data, signature))
                }
            }
        }
    }

    override suspend fun validate(logging: TestLoggingContext, api: TestVectorApi, provider: CryptographyProvider, algorithm: HMAC) {
        val keys = buildMap {
            api.keys.getParameters<KeyParameters> { (digestName), parametersId ->
                val keyDecoder = algorithm.keyDecoder(digest(digestName))
                api.keys.getData<KeyData>(parametersId) { (formats), keyReference ->
                    val keys = formats.mapNotNull { (stringFormat, data) ->
                        keyDecoder.decodeFrom(
                            format = when (stringFormat) {
                                StringKeyFormat.RAW -> HMAC.Key.Format.RAW
                                StringKeyFormat.JWK -> HMAC.Key.Format.JWK.takeIf { provider.supportsJwk }
                                else                -> error("Unsupported key format: $stringFormat") //TODO
                            },
                            input = data
                        )
                    }
                    keys.forEach { key ->
                        formats[StringKeyFormat.RAW]?.let { bytes ->
                            key.encodeTo(HMAC.Key.Format.RAW).assertContentEquals(bytes)
                        }
                    }
                    put(keyReference, keys)
                }
            }
        }
        api.signatures.getParameters<TestVectorParameters.Empty> { _, parametersId ->
            api.signatures.getData<SignatureData>(parametersId) { (keyReference, data, signature), _ ->
                keys.getValue(keyReference).forEach { key ->
                    val verifier = key.signatureVerifier()
                    val generator = key.signatureGenerator()

                    verifier.verifySignature(data, signature).assertTrue()
                    verifier.verifySignature(data, generator.generateSignature(data)).assertTrue()
                }
            }
        }
    }
}
