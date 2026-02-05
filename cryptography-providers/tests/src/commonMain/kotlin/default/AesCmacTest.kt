/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.default

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.random.*
import kotlin.test.*

abstract class AesCmacTest(provider: CryptographyProvider) : AesBasedTest<AES.CMAC>(AES.CMAC, provider) {

    @Test
    fun verifyResult() = runTestForEachKeySize {
        val key = algorithm.keyGenerator(keySize).generateKey()
        val data = CryptographyRandom.nextBytes(100)
        val signature = key.signatureGenerator().generateSignature(data)
        assertTrue(key.signatureVerifier().tryVerifySignature(data, signature))
    }
}