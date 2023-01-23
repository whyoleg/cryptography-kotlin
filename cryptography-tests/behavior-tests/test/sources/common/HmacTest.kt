package dev.whyoleg.cryptography.tests.behavior

import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.test.utils.*
import kotlin.math.*
import kotlin.test.*

class HmacTest {

    @Test
    fun testSizes() = runTestForEachAlgorithm(HMAC) {
        generateDigests { digest, digestSize ->
            val key = algorithm.keyGenerator(digest).generateKey()
            assertEquals(digestSize, key.encodeTo(HMAC.Key.Format.RAW).size)
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
