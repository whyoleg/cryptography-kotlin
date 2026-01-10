/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.default

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import dev.whyoleg.cryptography.random.*
import kotlinx.io.bytestring.*
import kotlin.test.*

private const val ivSize = 16

abstract class AesCfb8Test(provider: CryptographyProvider) : AesBasedTest<AES.CFB8>(AES.CFB8, provider) {
    @Test
    fun testSizes() = runTestForEachKeySize {
        val key = algorithm.keyGenerator(keySize).generateKey()
        assertEquals(keySize.inBytes, key.encodeToByteString(AES.Key.Format.RAW).size)

        key.cipher().run {
            // CFB8: ciphertext.size = IV + plaintext
            assertEquals(ivSize + 0, encrypt(ByteArray(0)).size)
            assertEquals(ivSize + 15, encrypt(ByteArray(15)).size)
            assertEquals(ivSize + 16, encrypt(ByteArray(16)).size)
            assertEquals(ivSize + 17, encrypt(ByteArray(17)).size)
            assertEquals(ivSize + 100, encrypt(ByteArray(100)).size)
            assertEquals(ivSize + 319, encrypt(ByteArray(319)).size)
            assertEquals(ivSize + 320, encrypt(ByteArray(320)).size)
            assertEquals(ivSize + 321, encrypt(ByteArray(321)).size)

            // too short
            assertFails { decrypt(ByteArray(0)) }
            assertFails { decrypt(ByteArray(ivSize - 1)) }
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

        val result = runCatching {
            wrongKey.cipher().decrypt(ciphertext)
        }

        result.onFailure {
            // expected
        }.onSuccess {
            // CFB8 has no authentication - decryption with wrong key
            // succeeds but produces garbage instead of failing
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
