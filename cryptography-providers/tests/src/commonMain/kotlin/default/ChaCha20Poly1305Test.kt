/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.default

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import dev.whyoleg.cryptography.random.*
import kotlinx.io.bytestring.*
import kotlin.test.*

private const val ivSize = 12
private const val tagSize = 16

abstract class ChaCha20Poly1305Test(provider: CryptographyProvider) : AlgorithmTest<ChaCha20Poly1305>(ChaCha20Poly1305, provider),
    CipherTest {
    @Test
    fun testSizes() = testWithAlgorithm {
        val key = algorithm.keyGenerator().generateKey()
        assertEquals(32, key.encodeToByteString(ChaCha20Poly1305.Key.Format.RAW).size)

        key.cipher().run {
            listOf(0, 15, 16, 17, 319, 320, 321).forEach { inputSize ->
                assertEquals(ivSize + inputSize + tagSize, encrypt(ByteArray(inputSize)).size)
                val iv = CryptographyRandom.nextBytes(ivSize)
                assertEquals(inputSize + tagSize, encryptWithIv(iv, ByteArray(inputSize)).size)
            }
        }
    }

    @Test
    fun decryption() = testWithAlgorithm {
        val data = CryptographyRandom.nextBytes(100)

        val key = algorithm.keyGenerator().generateKey()

        val ciphertext = key.cipher().encrypt(data)
        key.cipher().encrypt(ByteString()) // reset nonce ...
        val plaintext = key.cipher().decrypt(ciphertext)

        assertContentEquals(data, plaintext)
    }

    @Test
    fun decryptionWrongKey() = testWithAlgorithm {
        val data = CryptographyRandom.nextBytes(100)

        val key = algorithm.keyGenerator().generateKey()
        val wrongKey = algorithm.keyGenerator().generateKey()

        val ciphertext = key.cipher().encrypt(data)

        assertFails { wrongKey.cipher().decrypt(ciphertext) }
    }

    @Test
    fun testFunctions() = testWithAlgorithm {
        if (!supportsFunctions()) return@testWithAlgorithm

        val key = algorithm.keyGenerator().generateKey()
        val cipher = key.cipher()
        repeat(100) {
            val size = CryptographyRandom.nextInt(20000)
            val data = ByteString(CryptographyRandom.nextBytes(size))
            assertCipherViaFunction(cipher, cipher, data)
        }
    }

    @Test
    fun testFunctionsWithIv() = testWithAlgorithm {
        if (!supportsFunctions()) return@testWithAlgorithm

        val key = algorithm.keyGenerator().generateKey()
        val cipher = key.cipher()
        repeat(100) {
            val size = CryptographyRandom.nextInt(20000)
            val data = ByteString(CryptographyRandom.nextBytes(size))
            assertCipherWithIvViaFunction(cipher, cipher, ivSize, data)
        }
    }
}
