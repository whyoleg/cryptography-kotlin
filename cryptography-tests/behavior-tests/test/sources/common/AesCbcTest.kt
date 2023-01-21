package dev.whyoleg.cryptography.tests.behavior

import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.test.utils.*
import kotlin.test.*

private const val blockSize = 16
private const val ivSize = 16

class AesCbcTest {
    @Test
    fun testEncryptSizes() = runTestForEachAlgorithm(AES.CBC) {
        generateSymmetricKeySize { keySize ->
            if (!supportsKeySize(keySize.value.inBits)) return@generateSymmetricKeySize
            val key = algorithm.keyGenerator(keySize).generateKey()

            key.cipher(padding = true).run {
                assertEquals(ivSize + blockSize * 1, encrypt(ByteArray(0)).size)
                assertEquals(ivSize + blockSize * 1, encrypt(ByteArray(15)).size)
                assertEquals(ivSize + blockSize * 2, encrypt(ByteArray(16)).size)
                assertEquals(ivSize + blockSize * 2, encrypt(ByteArray(17)).size)
                assertEquals(ivSize + blockSize * 20, encrypt(ByteArray(319)).size)
                assertEquals(ivSize + blockSize * 21, encrypt(ByteArray(320)).size)
                assertEquals(ivSize + blockSize * 21, encrypt(ByteArray(321)).size)
            }
            if (supportsPadding(padding = false)) key.cipher(padding = false).run {
                assertEquals(ivSize + blockSize * 0, encrypt(ByteArray(0)).size)
                assertEquals(ivSize + blockSize * 1, encrypt(ByteArray(16)).size)
                assertEquals(ivSize + blockSize * 20, encrypt(ByteArray(320)).size)
            }
        }
    }

    @Test
    fun testKeySizes() = runTestForEachAlgorithm(AES.CBC) {
        generateSymmetricKeySize { keySize ->
            if (!supportsKeySize(keySize.value.inBits)) return@generateSymmetricKeySize
            assertEquals(keySize.value.inBytes, algorithm.keyGenerator(keySize).generateKey().encodeTo(AES.Key.Format.RAW).size)
        }
    }
}
