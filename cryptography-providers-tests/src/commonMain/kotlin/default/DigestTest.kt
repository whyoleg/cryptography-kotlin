/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.default

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.api.*
import dev.whyoleg.cryptography.random.*
import kotlinx.io.*
import kotlinx.io.bytestring.*
import kotlin.math.*
import kotlin.test.*

abstract class DigestTest(provider: CryptographyProvider) : ProviderTest(provider) {

    private fun test(algorithmId: CryptographyAlgorithmId<Digest>, digestSize: Int) =
        testAlgorithm(algorithmId) {
            if (!supportsDigest(algorithmId)) return@testAlgorithm

            val hasher = algorithm.hasher()
            assertEquals(digestSize, hasher.hash(ByteArray(0)).size)
            repeat(8) { n ->
                val size = 10.0.pow(n).toInt()
                val data = CryptographyRandom.nextBytes(size)
                val result = hasher.hash(data)
                assertEquals(digestSize, result.size)
                assertContentEquals(result, hasher.hash(data))
            }
        }

    @Test
    fun testMD5() = test(MD5, 16)

    @Test
    fun testSHA1() = test(SHA1, 20)

    @Test
    fun testSHA224() = test(SHA224, 28)

    @Test
    fun testSHA256() = test(SHA256, 32)

    @Test
    fun testSHA384() = test(SHA384, 48)

    @Test
    fun testSHA512() = test(SHA512, 64)

    @Test
    fun testSHA3_224() = test(SHA3_224, 28)

    @Test
    fun testSHA3_256() = test(SHA3_256, 32)

    @Test
    fun testSHA3_384() = test(SHA3_384, 48)

    @Test
    fun testSHA3_512() = test(SHA3_512, 64)

    @Test
    fun testFunctionIndexes() = testAlgorithm(SHA256) {
        if (!supportsFunctions()) return@testAlgorithm

        val hashFunction = algorithm.hasher().createHashFunction()
        val array = ByteArray(10)

        assertFails { hashFunction.update(array, -1, 10) }
        assertFails { hashFunction.update(array, 0, -1) }
        assertFails { hashFunction.update(array, 20, 10) }
        assertFails { hashFunction.update(array, 0, 20) }

        hashFunction.update(array)
    }

    @Test
    fun testFunctionChunked() = testAlgorithm(SHA256) {
        if (!supportsFunctions()) return@testAlgorithm

        val hasher = algorithm.hasher()
        val bytes = ByteString(CryptographyRandom.nextBytes(10000))

        val digest = hasher.hash(bytes)
        hasher.createHashFunction().use { function ->
            repeat(10) {
                function.update(bytes, it * 1000, (it + 1) * 1000)
            }
            assertContentEquals(digest, function.hash())
        }
    }

    @Test
    fun testFunctionReuse() = testAlgorithm(SHA256) {
        if (!supportsFunctions()) return@testAlgorithm

        val hasher = algorithm.hasher()
        val bytes1 = ByteString(CryptographyRandom.nextBytes(10000))
        val bytes2 = ByteString(CryptographyRandom.nextBytes(10000))

        val digest1 = hasher.hash(bytes1)
        val digest2 = hasher.hash(bytes2)
        hasher.createHashFunction().use { function ->
            function.update(bytes1)
            assertContentEquals(digest1, function.hash())

            function.update(bytes2)
            assertContentEquals(digest2, function.hash())

            // update and then discard
            function.update(bytes1)
            function.update(bytes1)
            function.reset()
            // update after reset
            function.update(bytes1)
            assertContentEquals(digest1, function.hash())
        }
    }

    @Test
    fun testFunctionSource() = testAlgorithm(SHA256) {
        val hasher = algorithm.hasher()

        val bytes = ByteString(CryptographyRandom.nextBytes(10000))
        val source = Buffer()
        source.write(bytes)
        val digest = hasher.hash(bytes)

        assertContentEquals(digest, hasher.hash(source.copy()))

        if (!supportsFunctions()) return@testAlgorithm
        hasher.createHashFunction().use { function ->
            assertContentEquals(bytes, function.updatingSource(source).buffered().readByteString())
            assertContentEquals(digest, function.hash())
        }
    }
}
