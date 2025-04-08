package dev.whyoleg.cryptography.providers.tests.default

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.api.*
import kotlin.test.*

abstract class CmacTest(provider: CryptographyProvider) : AlgorithmTest<CMAC>(CMAC, provider) {

    private class CmacTestScope(
        logger: TestLogger,
        context: TestContext,
        provider: CryptographyProvider,
        algorithm: CMAC,
    ) : AlgorithmTestScope<CMAC>(logger, context, provider, algorithm)

    private fun runTestWithScope(block: suspend CmacTestScope.() -> Unit) = testWithAlgorithm {
        block(CmacTestScope(logger, context, provider, algorithm))
    }

    @Test
    fun test1() = runTestWithScope {
        val key = "key".encodeToByteArray()
        val salt = "salt".encodeToByteArray()
        val cmac = provider.get(CMAC)
        val cmacKey = cmac.keyGenerator(cipherParameters = key).generateKeyBlocking()
        cmacKey.update(salt)
        val diversifiedKey = cmacKey.encodeToByteArrayBlocking(CMAC.Key.Format.RAW)
        assertNotNull(diversifiedKey)
    }

}