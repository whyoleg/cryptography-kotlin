/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.default

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import dev.whyoleg.cryptography.random.*
import kotlin.test.*

abstract class Poly1305Test(provider: CryptographyProvider) : AlgorithmTest<Poly1305>(Poly1305, provider) {

    @Test
    fun testSizes() = testWithAlgorithm {
        val key = algorithm.keyGenerator().generateKey()
        assertEquals(32, key.encodeToByteString(Poly1305.Key.Format.RAW).size)
        assertEquals(16, key.signatureGenerator().generateSignature(ByteArray(0)).size)
    }

    @Test
    fun verifyResult() = testWithAlgorithm {
        val key = algorithm.keyGenerator().generateKey()
        val data = CryptographyRandom.nextBytes(100)
        val signature = key.signatureGenerator().generateSignature(data)
        assertTrue(key.signatureVerifier().tryVerifySignature(data, signature))
    }

    @Test
    fun verifyWrongKey() = testWithAlgorithm {
        val key = algorithm.keyGenerator().generateKey()
        val wrongKey = algorithm.keyGenerator().generateKey()
        val data = CryptographyRandom.nextBytes(100)
        val signature = key.signatureGenerator().generateSignature(data)
        assertFalse(wrongKey.signatureVerifier().tryVerifySignature(data, signature))
    }
}
