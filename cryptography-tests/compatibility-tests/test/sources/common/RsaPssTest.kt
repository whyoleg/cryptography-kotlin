package dev.whyoleg.cryptography.tests.compatibility

import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.tests.compatibility.api.*
import kotlinx.serialization.*
import kotlin.test.*

private const val saltIterations = 5
private const val signatureIterations = 5
private const val maxSaltSize = 100
private const val maxDataSize = 10000

class RsaPssTest : RsaBasedTest<RSA.PSS.PublicKey, RSA.PSS.PrivateKey, RSA.PSS.KeyPair, RSA.PSS>(RSA.PSS) {

    @Serializable
    private data class SignatureParameters(val saltSizeBytes: Int) : TestParameters

    override suspend fun CompatibilityTestContext<RSA.PSS>.generate() {
        val saltSizes = buildList {
            repeat(saltIterations) {
                val saltSize = CryptographyRandom.nextInt(maxSaltSize)
                val id = api.signatures.saveParameters(SignatureParameters(saltSize))
                add(id to saltSize.bytes)
            }
        }
        generateKeys { keyPair, keyReference, _ ->
            saltSizes.forEach { (signatureParametersId, saltSize) ->
                logger.log { "salt.size      = ${saltSize.inBytes}" }

                val signer = keyPair.privateKey.signatureGenerator(saltSize)
                val verifier = keyPair.publicKey.signatureVerifier(saltSize)

                repeat(signatureIterations) {
                    val dataSize = CryptographyRandom.nextInt(maxDataSize)
                    logger.log { "data.size      = $dataSize" }
                    val data = CryptographyRandom.nextBytes(dataSize)
                    val signature = signer.generateSignature(data)
                    logger.log { "signature.size = ${signature.size}" }

                    assertTrue(verifier.verifySignature(data, signature), "Initial Verify")

                    api.signatures.saveData(signatureParametersId, SignatureData(keyReference, data, signature))
                }
            }
        }
    }

    override suspend fun CompatibilityTestContext<RSA.PSS>.validate() {
        val keyPairs = validateKeys()

        api.signatures.getParameters<SignatureParameters> { (saltSizeBytes), parametersId ->
            api.signatures.getData<SignatureData>(parametersId) { (keyReference, data, signature), _ ->
                val (publicKeys, privateKeys) = keyPairs.getValue(keyReference)
                val verifiers = publicKeys.map { it.signatureVerifier(saltSizeBytes.bytes) }
                val generators = privateKeys.map { it.signatureGenerator(saltSizeBytes.bytes) }

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