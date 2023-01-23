package dev.whyoleg.cryptography.tests.behavior

import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.test.utils.*
import kotlin.math.*
import kotlin.test.*

class RsaPssTest {

    @Test
    fun testSizes() = runTestForEachAlgorithm(RSA.PSS) {
        generateRsaKeySizes { keySize ->
            generateDigests { digest, _ ->
                val signatureGenerator = algorithm.keyPairGenerator(keySize, digest).generateKey().privateKey.signatureGenerator(10.bytes)

                assertEquals(keySize.inBytes, signatureGenerator.generateSignature(ByteArray(0)).size)
                repeat(8) { n ->
                    val size = 10.0.pow(n).toInt()
                    val data = CryptographyRandom.nextBytes(size)
                    assertEquals(keySize.inBytes, signatureGenerator.generateSignature(data).size)
                }
            }
        }
    }
}
