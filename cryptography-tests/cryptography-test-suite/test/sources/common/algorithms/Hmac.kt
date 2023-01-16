package dev.whyoleg.cryptography.test.suite.algorithms

import dev.whyoleg.cryptography.algorithms.symmetric.mac.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.test.api.*
import dev.whyoleg.cryptography.test.suite.*
import dev.whyoleg.cryptography.test.suite.generators.*

private const val keyIterations = 10
private const val dataIterations = 10
private const val maxDataSize = 10000

private val generate = TestAction { api, provider ->
    val algorithm = provider.get(HMAC)

    digests { digest, _ ->
        val keyGenerator = algorithm.keyGenerator(digest)
        repeat(keyIterations) {
            val key = keyGenerator.generateKey()
            val keyId = api.keys.save(
                algorithm = algorithm.id.name,
                params = digest.name,
                data = KeyData {
                    put(StringKeyFormat.RAW, key.encodeTo(HMAC.Key.Format.RAW))
                    if (provider.supportsJwk) put(StringKeyFormat.JWK, key.encodeTo(HMAC.Key.Format.JWK))
                }
            )

            val signatureGenerator = key.signatureGenerator()
            val signatureVerifier = key.signatureVerifier()
            repeat(dataIterations) {
                val dataSize = CryptographyRandom.nextInt(maxDataSize)
                println("generate: data.size  = $dataSize")
                val data = CryptographyRandom.nextBytes(dataSize)
                val signature = signatureGenerator.generateSignature(data)
                println("generate: signature.size  = ${signature.size}")

                signatureVerifier.verifySignature(data, signature).assertTrue()

                api.signatures.save(
                    algorithm = algorithm.id.name,
                    params = digest.name,
                    data = SignatureData(keyId, digest.name, data, signature)
                )
            }
        }
    }
}

private val validate = TestAction { api, provider ->
    val algorithm = provider.get(HMAC)

    digests { digest, _ ->
        val keyDecoder = algorithm.keyDecoder(digest)
        api.signatures.getAll(
            algorithm = algorithm.id.name,
            params = digest.name
        ).forEach { (signatureData) ->
            val keyData = api.keys.get(
                algorithm = algorithm.id.name,
                params = signatureData.keyParams,
                id = signatureData.keyId
            ).data

            keyData.formats.forEach { (stringFormat, data) ->
                val key = keyDecoder.decodeFrom(
                    format = when (stringFormat) {
                        StringKeyFormat.RAW -> HMAC.Key.Format.RAW
                        StringKeyFormat.JWK -> HMAC.Key.Format.JWK.takeIf { provider.supportsJwk }
                        else                -> error("Unsupported key format: $stringFormat") //TODO
                    },
                    input = data
                ) ?: return@forEach

                keyData.formats[StringKeyFormat.RAW]?.let { bytes ->
                    key.encodeTo(HMAC.Key.Format.RAW).assertContentEquals(bytes)
                }
                //TODO: JWK should be checked by JSON equality, and not per bytes (use kx.serialization)

                key.signatureVerifier().run {
                    key.signatureGenerator().run {
                        verifySignature(signatureData.data, signatureData.signature).assertTrue()
                        verifySignature(signatureData.data, generateSignature(signatureData.data)).assertTrue()
                    }
                }
            }
        }
    }
}

val hmac = TestSuite("HMAC", generate = generate, validate = validate)
