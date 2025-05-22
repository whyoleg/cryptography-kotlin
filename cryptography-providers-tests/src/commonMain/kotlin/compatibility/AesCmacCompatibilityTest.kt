package dev.whyoleg.cryptography.providers.tests.compatibility

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.api.assertVerifySignature
import dev.whyoleg.cryptography.providers.tests.api.compatibility.*
import dev.whyoleg.cryptography.random.*
import kotlinx.io.bytestring.*
import kotlinx.serialization.*
import kotlin.test.*

private const val maxPlaintextSize = 10000

abstract class AesCmacCompatibilityTest(provider: CryptographyProvider) :
    AesBasedCompatibilityTest<AES.CMAC.Key, AES.CMAC>(AES.CMAC, provider) {

    override suspend fun CompatibilityTestScope<AES.CMAC>.generate(isStressTest: Boolean) {
        val dataIterations = when {
            isStressTest -> 10
            else         -> 5
        }

        val signatureParametersId = api.signatures.saveParameters(TestParameters.Empty)
        generateKeys(isStressTest) { key, keyReference, _ ->
            val signer = key.signatureGenerator()
            val verifier = key.signatureVerifier()
            repeat(dataIterations) {
                val dataSize = CryptographyRandom.nextInt(maxPlaintextSize)
                logger.log { "dataSize  = $dataSize" }

                val data = ByteString(CryptographyRandom.nextBytes(dataSize))
                val signature = signer.generateSignatureBlocking(data)
                logger.log { "signature.size = ${signature.size}" }

                verifier.assertVerifySignature(data, signature, "Initial Verify")
                api.ciphers.saveData(signatureParametersId, SignatureData(keyReference, data, signature))
            }
        }
    }

    override suspend fun CompatibilityTestScope<AES.CMAC>.validate() {
        val keys = validateKeys()
        api.ciphers.getParameters<TestParameters.Empty> { _, parametersId, _ ->
            api.ciphers.getData<SignatureData>(parametersId) { (keyReference, data, signature), _, _ ->
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
