package dev.whyoleg.cryptography.providers.tests.compatibility

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.api.compatibility.*
import dev.whyoleg.cryptography.random.*
import kotlinx.io.bytestring.*
import kotlinx.serialization.*
import kotlin.test.*

private const val maxPlaintextSize = 10000

abstract class AesCmacCompatibilityTest(provider: CryptographyProvider) :
    AesBasedCompatibilityTest<AES.CMAC.Key, AES.CMAC>(AES.CMAC, provider) {

    @Serializable
    private data class SignatureParameters(
        val mockedPadding: Boolean,
    ) : TestParameters

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

                assertTrue(verifier.tryVerifySignatureBlocking(data, signature), "Initial Verify")
                api.ciphers.saveData(signatureParametersId, SignatureData(keyReference, data, signature))
            }
        }
    }

    override suspend fun CompatibilityTestScope<AES.CMAC>.validate() {
        val keys = validateKeys()
        api.ciphers.getParameters<SignatureParameters> { _, parametersId, _ ->
            api.ciphers.getData<SignatureData>(parametersId) { (keyReference, data, signature), _, _ ->
                val (verify, _) = keys[keyReference] ?: return@getData
                val verifiers = verify.signatureVerifier()
                assertTrue(verifiers.tryVerifySignatureBlocking(data, signature), "Verify")
            }
        }
    }
}
