/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.behavior

import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.random.*
import kotlin.test.*

private const val ivSize = 12
private const val blockSize = 16

class AesGcmTest : AesTest<AES.GCM>(AES.GCM) {
    @Test
    fun testSizes() = runTestForEachKeySize {
        val key = algorithm.keyGenerator(keySize).generateKey()
        assertEquals(keySize.value.inBytes, key.encodeTo(AES.Key.Format.RAW).size)

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
}
