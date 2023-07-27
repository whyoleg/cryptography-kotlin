/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.behavior

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.providers.tests.support.*
import dev.whyoleg.cryptography.random.*
import kotlin.math.*
import kotlin.test.*

class HmacTest {

    private class HmacTestScope(
        logger: TestLogger,
        context: TestContext,
        provider: CryptographyProvider,
        algorithm: HMAC,
        val digest: CryptographyAlgorithmId<Digest>,
        val digestSize: Int,
        val digestBlockSize: Int,
    ) : AlgorithmTestScope<HMAC>(logger, context, provider, algorithm)

    private fun runTestForEachDigest(block: suspend HmacTestScope.() -> Unit) = runTestForEachAlgorithm(HMAC) {
        //all values are in bytes
        listOf(
            Triple(SHA1, 20, 64),
            Triple(SHA256, 32, 64),
            Triple(SHA384, 48, 128),
            Triple(SHA512, 64, 128),
        ).forEach { (digest, digestSize, digestBlockSize) ->
            block(HmacTestScope(logger, context, provider, algorithm, digest, digestSize, digestBlockSize))
        }
    }

    @Test
    fun testSizes() = runTestForEachDigest {
        val key = algorithm.keyGenerator(digest).generateKey()
        assertEquals(digestBlockSize, key.encodeTo(HMAC.Key.Format.RAW).size)
        val signatureGenerator = key.signatureGenerator()

        assertEquals(digestSize, signatureGenerator.generateSignature(ByteArray(0)).size)
        repeat(8) { n ->
            val size = 10.0.pow(n).toInt()
            val data = CryptographyRandom.nextBytes(size)
            assertEquals(digestSize, signatureGenerator.generateSignature(data).size)
        }
    }

    @Test
    fun verifyNoFail() = runTestForEachDigest {
        val key = algorithm.keyGenerator(digest).generateKey()
        assertFalse(key.signatureVerifier().verifySignature(ByteArray(0), ByteArray(0)))
        assertFalse(key.signatureVerifier().verifySignature(ByteArray(10), ByteArray(0)))
        assertFalse(key.signatureVerifier().verifySignature(ByteArray(10), ByteArray(10)))
    }

    @Test
    fun verifyResult() = runTestForEachDigest {
        val key = algorithm.keyGenerator(digest).generateKey()
        val data = CryptographyRandom.nextBytes(100)
        val signature = key.signatureGenerator().generateSignature(data)
        assertTrue(key.signatureVerifier().verifySignature(data, signature))
    }

    @Test
    fun verifyResultWrongKey() = runTestForEachDigest {
        val keyGenerator = algorithm.keyGenerator(digest)
        val key = keyGenerator.generateKey()
        val wrongKey = keyGenerator.generateKey()
        val data = CryptographyRandom.nextBytes(100)
        val signature = key.signatureGenerator().generateSignature(data)
        assertFalse(wrongKey.signatureVerifier().verifySignature(data, signature))
    }
}
