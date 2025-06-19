/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.default

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.api.*
import dev.whyoleg.cryptography.random.*
import kotlinx.io.bytestring.*
import kotlin.test.*

private const val blockSize = 16
private const val ivSize = 16

abstract class AesCbcTest(provider: CryptographyProvider) : AesBasedTest<AES.CBC>(AES.CBC, provider) {
    @Test
    fun testSizes() = runTestForEachKeySize {
        val key = algorithm.keyGenerator(keySize).generateKey()
        assertEquals(keySize.inBytes, key.encodeToByteString(AES.Key.Format.RAW).size)

        key.cipher(padding = true).run {
            assertEquals(ivSize + blockSize * 1, encrypt(ByteArray(0)).size)
            assertEquals(ivSize + blockSize * 1, encrypt(ByteArray(15)).size)
            assertEquals(ivSize + blockSize * 2, encrypt(ByteArray(16)).size)
            assertEquals(ivSize + blockSize * 2, encrypt(ByteArray(17)).size)
            assertEquals(ivSize + blockSize * 20, encrypt(ByteArray(319)).size)
            assertEquals(ivSize + blockSize * 21, encrypt(ByteArray(320)).size)
            assertEquals(ivSize + blockSize * 21, encrypt(ByteArray(321)).size)

            // too short
            assertFails { decrypt(ByteArray(0)) }
            assertFails { decrypt(ByteArray(15)) }


            // not padded
            assertFails { decrypt(ByteArray(17)) }
            assertFails { decrypt(ByteArray(319)) }
            assertFails { decrypt(ByteArray(321)) }
        }
        if (supportsPadding(padding = false)) key.cipher(padding = false).run {
            assertEquals(ivSize + blockSize * 0, encrypt(ByteArray(0)).size)
            assertEquals(ivSize + blockSize * 1, encrypt(ByteArray(16)).size)
            assertEquals(ivSize + blockSize * 20, encrypt(ByteArray(320)).size)

            // too short
            assertFails { decrypt(ByteArray(0)) }
            assertFails { decrypt(ByteArray(15)) }

            // not padded
            assertFails { decrypt(ByteArray(17)) }
            assertFails { decrypt(ByteArray(319)) }
            assertFails { decrypt(ByteArray(321)) }

            // only IV, empty ciphertext
            decrypt(ByteArray(ivSize))
        }
    }

    @Test
    fun decryption() = runTestForEachKeySize {
        val data = CryptographyRandom.nextBytes(100)

        val key = algorithm.keyGenerator(keySize).generateKey()

        val ciphertext = key.cipher(padding = true).encrypt(data)
        val plaintext = key.cipher(padding = true).decrypt(ciphertext)

        assertContentEquals(data, plaintext)
    }

    @Test
    fun decryptionWrongKey() = runTestForEachKeySize {
        val data = CryptographyRandom.nextBytes(100)

        val key = algorithm.keyGenerator(keySize).generateKey()
        val wrongKey = algorithm.keyGenerator(keySize).generateKey()

        val ciphertext = key.cipher(padding = true).encrypt(data)

        val result = runCatching {
            wrongKey.cipher(padding = true).decrypt(ciphertext)
        }

        result.onFailure {
            // expected
        }.onSuccess {
            // sometimes we can decrypto with the wrong key
            // TODO: looks like something is wrong with this test
            assertNotEquals(data, it)
        }
    }

    @Test
    fun testFunctions() = runTestForEachKeySize {
        if (!supportsFunctions()) return@runTestForEachKeySize

        val key = algorithm.keyGenerator(keySize).generateKey()
        val cipher = key.cipher()
        repeat(100) {
            val size = CryptographyRandom.nextInt(20000)
            val data = ByteString(CryptographyRandom.nextBytes(size))
            assertCipherViaFunction(cipher, cipher, data)
        }
    }

    @Test
    fun testFunctionsWithIv() = runTestForEachKeySize {
        if (!supportsFunctions()) return@runTestForEachKeySize

        val key = algorithm.keyGenerator(keySize).generateKey()
        val cipher = key.cipher()
        repeat(100) {
            val size = CryptographyRandom.nextInt(20000)
            val data = ByteString(CryptographyRandom.nextBytes(size))
            assertCipherWithIvViaFunction(cipher, cipher, ivSize, data)
        }
    }
}
