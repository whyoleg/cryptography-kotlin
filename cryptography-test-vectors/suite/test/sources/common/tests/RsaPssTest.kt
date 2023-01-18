package dev.whyoleg.cryptography.test.vectors.suite.tests

import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.provider.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.test.support.*
import dev.whyoleg.cryptography.test.vectors.suite.*
import dev.whyoleg.cryptography.test.vectors.suite.api.*
import kotlinx.serialization.*

private const val saltIterations = 5
private const val signatureIterations = 5
private const val maxSaltSize = 100
private const val maxDataSize = 10000

class RsaPssTest : RsaBasedTest<RSA.PSS.PublicKey, RSA.PSS.PrivateKey, RSA.PSS.KeyPair, RSA.PSS>(RSA.PSS) {

    @Serializable
    private data class SignatureParameters(val saltSizeBytes: Int) : TestVectorParameters

    override suspend fun generate(logging: TestLoggingContext, api: TestVectorApi, provider: CryptographyProvider, algorithm: RSA.PSS) {
        val saltSizes = buildList {
            repeat(saltIterations) {
                val saltSize = CryptographyRandom.nextInt(maxSaltSize)
                val id = api.signatures.saveParameters(SignatureParameters(saltSize))
                add(id to saltSize.bytes)
            }
        }
        generateKeys(logging, api, provider, algorithm) { keyPair, keyReference, _ ->
            saltSizes.forEach { (signatureParametersId, saltSize) ->
                logging.log("salt.size      = ${saltSize.inBytes}")

                val signer = keyPair.privateKey.signatureGenerator(saltSize)
                val verifier = keyPair.publicKey.signatureVerifier(saltSize)

                repeat(signatureIterations) {
                    val dataSize = CryptographyRandom.nextInt(maxDataSize)
                    logging.log("data.size      = $dataSize")
                    val data = CryptographyRandom.nextBytes(dataSize)
                    val signature = signer.generateSignature(data)
                    logging.log("signature.size = ${signature.size}")

                    verifier.verifySignature(data, signature).assertTrue()

                    api.signatures.saveData(signatureParametersId, SignatureData(keyReference, data, signature))
                }
            }
        }
    }

    override suspend fun validate(logging: TestLoggingContext, api: TestVectorApi, provider: CryptographyProvider, algorithm: RSA.PSS) {
        val keyPairs = validateKeys(logging, api, provider, algorithm)

        api.signatures.getParameters<SignatureParameters> { (saltSizeBytes), parametersId ->
            api.signatures.getData<SignatureData>(parametersId) { (keyReference, data, signature), _ ->
                val (publicKeys, privateKeys) = keyPairs.getValue(keyReference)
                val verifiers = publicKeys.map { it.signatureVerifier(saltSizeBytes.bytes) }
                val generators = privateKeys.map { it.signatureGenerator(saltSizeBytes.bytes) }

                verifiers.forEach { verifier ->
                    verifier.verifySignature(data, signature).assertTrue()

                    generators.forEach { generator ->
                        verifier.verifySignature(data, generator.generateSignature(data)).assertTrue()
                    }
                }
            }
        }
    }
}
