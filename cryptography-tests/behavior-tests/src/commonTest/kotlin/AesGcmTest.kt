/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.behavior

import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.algorithms.symmetric.*
import dev.whyoleg.cryptography.test.utils.*
import kotlin.test.*

private const val ivSize = 12
private const val blockSize = 16

class AesGcmTest {
    @Test
    fun testSizes() = runTestForEachAlgorithm(AES.GCM) {
        generateSymmetricKeySize { keySize ->
            if (!supportsKeySize(keySize.value.inBits)) return@generateSymmetricKeySize

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
    }
}
