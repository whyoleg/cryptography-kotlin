/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.behavior

import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.providers.tests.support.*
import dev.whyoleg.cryptography.random.*
import kotlin.math.*
import kotlin.test.*

class DigestTest {

    private fun test(algorithmId: CryptographyAlgorithmId<Digest>, digestSize: Int) = runTestForEachAlgorithm(algorithmId) {
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
    fun testSHA256() = test(SHA256, 32)

    @Test
    fun testSHA384() = test(SHA384, 48)

    @Test
    fun testSHA512() = test(SHA512, 64)
}
