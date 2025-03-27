package dev.whyoleg.cryptography.providers.tests.compatibility

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.api.compatibility.*
import dev.whyoleg.cryptography.random.*
import kotlinx.io.bytestring.*
import kotlin.test.*

abstract class CmacCompatibilityTest(provider: CryptographyProvider) : CompatibilityTest<CMAC>(CMAC, provider) {

    override suspend fun CompatibilityTestScope<CMAC>.generate(isStressTest: Boolean) {
        val signatureParametersId = api.signatures.saveParameters(TestParameters.Empty)

        val cmac = provider.get(CMAC)
        val key = CryptographyRandom.nextBytes(16)
        val salt = CryptographyRandom.nextBytes(16)

        cmac.init(key)
        cmac.update(salt)
        val result = cmac.doFinal()

        api.signatures.saveData(signatureParametersId, CmacData(ByteString(key), ByteString(salt), ByteString(result)))
    }

    override suspend fun CompatibilityTestScope<CMAC>.validate() {
        api.signatures.getParameters<TestParameters.Empty> { _, parametersId, _ ->
            api.signatures.getData<CmacData>(parametersId) { (key, salt, result), _, _ ->
                assertTrue(key.isNotEmpty())
                assertTrue(salt.isNotEmpty())
                assertTrue(result.isNotEmpty())
            }
        }

    }
}