/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.default

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.api.*
import dev.whyoleg.cryptography.random.*
import kotlin.test.*

abstract class AesCmacTest(provider: CryptographyProvider) : AesBasedTest<AES.CMAC>(AES.CMAC, provider) {

    private class AesCmacTestScope(
        logger: TestLogger,
        context: TestContext,
        provider: CryptographyProvider,
        algorithm: AES.CMAC,
    ) : AlgorithmTestScope<AES.CMAC>(logger, context, provider, algorithm)

    private fun runTestWithScope(block: suspend AesCmacTestScope.() -> Unit) = testWithAlgorithm {
        block(AesCmacTestScope(logger, context, provider, algorithm))
    }

    @Test
    fun verifyResult() = runTestWithScope {
        val key = algorithm.keyGenerator(128.bits).generateKey()
        val data = CryptographyRandom.nextBytes(100)
        val signature = key.signatureGenerator().generateSignature(data)
        assertTrue(key.signatureVerifier().tryVerifySignature(data, signature))
    }
}