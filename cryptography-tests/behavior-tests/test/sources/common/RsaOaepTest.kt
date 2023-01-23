package dev.whyoleg.cryptography.tests.behavior

import dev.whyoleg.cryptography.algorithms.asymmetric.*
import dev.whyoleg.cryptography.random.*
import dev.whyoleg.cryptography.test.utils.*
import kotlin.math.*
import kotlin.test.*

class RsaOaepTest {

    @Test
    fun testSizes() = runTestForEachAlgorithm(RSA.OAEP) {
        generateRsaKeySizes { keySize ->
            generateDigests { digest, digestSize ->
                val keyPair = algorithm.keyPairGenerator(keySize, digest).generateKey()
                assertEquals(keySize.inBytes + 38, keyPair.publicKey.encodeTo(RSA.PublicKey.Format.DER).size)
                val encryptor = keyPair.publicKey.encryptor()

                val maxSize = keySize.inBytes - 2 - 2 * digestSize

                assertEquals(keySize.inBytes, encryptor.encrypt(ByteArray(0)).size)
                assertEquals(keySize.inBytes, encryptor.encrypt(ByteArray(maxSize)).size)
                repeat(8) { n ->
                    val size = 10.0.pow(n).toInt()
                    if (size < maxSize) {
                        val data = CryptographyRandom.Default.nextBytes(size)
                        assertEquals(keySize.inBytes, encryptor.encrypt(data).size)
                    }
                }
            }
        }
    }
}
