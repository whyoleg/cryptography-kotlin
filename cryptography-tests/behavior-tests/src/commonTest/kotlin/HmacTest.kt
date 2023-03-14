/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.behavior

import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.test.utils.*
import kotlin.math.*
import kotlin.test.*

class HmacTest {

    @Test
    fun testSizes() = runTestForEachAlgorithm(HMAC) {
        //all values are in bytes
        listOf(
            Triple(SHA1, 20, 64),
            Triple(SHA256, 32, 64),
            Triple(SHA384, 48, 128),
            Triple(SHA512, 64, 128),
        ).forEach { (digest, digestSize, digestBlockSize) ->
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
    }
}
