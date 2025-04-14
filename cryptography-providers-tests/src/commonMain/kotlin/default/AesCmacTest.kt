/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.default

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.AES.*
import dev.whyoleg.cryptography.providers.tests.api.*
import kotlin.test.*

class AesCmacTest(provider: CryptographyProvider) : AesBasedTest<AES.CMAC>(AES.CMAC, provider) {

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
    fun testStuff() = runTestWithScope {
        val key = "key".encodeToByteArray()
        val salt = "salt".encodeToByteArray()

        val cmacProvider = provider.get(AES.CMAC)
        val decodedKey = cmacProvider.keyDecoder().decodeFromByteArrayBlocking(Key.Format.RAW, key)

        val signFunction = decodedKey.signatureGenerator().createSignFunction()
        signFunction.update(salt)
        val derivedKey = signFunction.signToByteArray()
    }
}