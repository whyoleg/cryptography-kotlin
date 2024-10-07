/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.default

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.api.*
import dev.whyoleg.cryptography.random.*
import kotlinx.io.bytestring.*
import kotlin.test.*

private const val ivSize = 12

abstract class AesGcmTest(provider: CryptographyProvider) : AesBasedTest<AES.GCM>(AES.GCM, provider) {
    @Test
    fun testSizes() = runTestForEachKeySize {
        val key = algorithm.keyGenerator(keySize).generateKey()
        assertEquals(keySize.inBytes, key.encodeToByteString(AES.Key.Format.RAW).size)

        listOf(96, 104, 112, 120, 128).forEach { tagSizeBits ->
            val tagSize = tagSizeBits.bits.inBytes
            key.cipher(tagSizeBits.bits).run {
                listOf(0, 15, 16, 17, 319, 320, 321).forEach { inputSize ->
                    assertEquals(ivSize + inputSize + tagSize, encrypt(ByteArray(inputSize)).size)
                }
            }
        }
    }

    @Test
    fun decryption() = runTestForEachKeySize {
        val data = CryptographyRandom.nextBytes(100)

        val key = algorithm.keyGenerator(keySize).generateKey()

        val ciphertext = key.cipher().encrypt(data)
        val plaintext = key.cipher().decrypt(ciphertext)

        assertContentEquals(data, plaintext)
    }

    @Test
    fun decryptionWrongKey() = runTestForEachKeySize {
        val data = CryptographyRandom.nextBytes(100)

        val key = algorithm.keyGenerator(keySize).generateKey()
        val wrongKey = algorithm.keyGenerator(keySize).generateKey()

        val ciphertext = key.cipher().encrypt(data)

        assertFails { wrongKey.cipher().decrypt(ciphertext) }
    }

    @Test
    fun testFunctions() = runTestForEachKeySize {
        if (!supportsFunctions()) return@runTestForEachKeySize

        val key = algorithm.keyGenerator(keySize).generateKey()
        listOf(96, 104, 112, 120, 128).forEach { tagSizeBits ->
            val cipher = key.cipher(tagSizeBits.bits)
            repeat(100) {
                val size = CryptographyRandom.nextInt(20000)
                val data = ByteString(CryptographyRandom.nextBytes(size))
                assertCipherViaFunction(cipher, cipher, data)
            }
        }
    }

    @Test
    fun testFunctionsWithIv() = runTestForEachKeySize {
        if (!supportsFunctions()) return@runTestForEachKeySize

        val key = algorithm.keyGenerator(keySize).generateKey()
        listOf(96, 104, 112, 120, 128).forEach { tagSizeBits ->
            val cipher = key.cipher(tagSizeBits.bits)
            repeat(100) {
                val size = CryptographyRandom.nextInt(20000)
                val data = ByteString(CryptographyRandom.nextBytes(size))
                assertCipherWithIvViaFunction(cipher, cipher, ivSize, data)
            }
        }
    }
}
