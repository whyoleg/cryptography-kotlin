/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.default

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import dev.whyoleg.cryptography.random.*
import kotlinx.io.bytestring.*
import kotlin.math.*
import kotlin.test.*

abstract class HmacTest(provider: CryptographyProvider) : AlgorithmTest<HMAC>(HMAC, provider), SignatureTest {

    private class HmacTestScope(
        logger: TestLogger,
        context: TestContext,
        provider: CryptographyProvider,
        algorithm: HMAC,
        val digest: CryptographyAlgorithmId<Digest>,
        val digestSize: Int,
        val digestBlockSize: Int,
    ) : AlgorithmTestScope<HMAC>(logger, context, provider, algorithm)

    private fun runTestForEachDigest(block: suspend HmacTestScope.() -> Unit) = testWithAlgorithm {
        //all values are in bytes
        listOf(
            Triple(SHA1, 20, 64),
            Triple(SHA224, 28, 64),
            Triple(SHA256, 32, 64),
            Triple(SHA384, 48, 128),
            Triple(SHA512, 64, 128),
            Triple(SHA3_224, 28, 144),
            Triple(SHA3_256, 32, 136),
            Triple(SHA3_384, 48, 104),
            Triple(SHA3_512, 64, 72),
        ).forEach { (digest, digestSize, digestBlockSize) ->
            if (!supportsDigest(digest)) return@forEach

            block(HmacTestScope(logger, context, provider, algorithm, digest, digestSize, digestBlockSize))
        }
    }

    @Test
    fun testSizes() = runTestForEachDigest {
        val key = algorithm.keyGenerator(digest).generateKey()
        assertEquals(digestBlockSize, key.encodeToByteString(HMAC.Key.Format.RAW).size)
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
        assertFalse(key.signatureVerifier().tryVerifySignature(ByteArray(0), ByteArray(0)))
        assertFalse(key.signatureVerifier().tryVerifySignature(ByteArray(10), ByteArray(0)))
        assertFalse(key.signatureVerifier().tryVerifySignature(ByteArray(10), ByteArray(10)))
    }

    @Test
    fun verifyResult() = runTestForEachDigest {
        val key = algorithm.keyGenerator(digest).generateKey()
        val data = CryptographyRandom.nextBytes(100)
        val signature = key.signatureGenerator().generateSignature(data)
        assertTrue(key.signatureVerifier().tryVerifySignature(data, signature))
    }

    @Test
    fun verifyResultWrongKey() = runTestForEachDigest {
        val keyGenerator = algorithm.keyGenerator(digest)
        val key = keyGenerator.generateKey()
        val wrongKey = keyGenerator.generateKey()
        val data = CryptographyRandom.nextBytes(100)
        val signature = key.signatureGenerator().generateSignature(data)
        assertFalse(wrongKey.signatureVerifier().tryVerifySignature(data, signature))
    }

    @Test
    fun testFunctions() = runTestForEachDigest {
        if (!supportsFunctions()) return@runTestForEachDigest

        val key = algorithm.keyGenerator(digest).generateKey()
        val signatureGenerator = key.signatureGenerator()
        val signatureVerifier = key.signatureVerifier()

        repeat(10) {
            val size = CryptographyRandom.nextInt(20000)
            val data = ByteString(CryptographyRandom.nextBytes(size))
            assertSignaturesViaFunction(signatureGenerator, signatureVerifier, data)
        }
    }
}
