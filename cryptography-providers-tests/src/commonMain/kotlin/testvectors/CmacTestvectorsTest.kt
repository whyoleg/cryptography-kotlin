package dev.whyoleg.cryptography.providers.tests.testvectors

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.api.*
import kotlin.test.*

abstract class CmacTestvectorsTest(provider: CryptographyProvider) : AlgorithmTest<CMAC>(CMAC, provider) {

    private fun testCase(key: ByteArray, salt: ByteArray, expected: ByteArray) {
        testWithAlgorithm {
            val key = algorithm.keyGenerator(key).generateKeyBlocking()
            key.update(salt)
            val result = key.encodeToByteArrayBlocking(CMAC.Key.Format.RAW)
            assertEquals(16, result.size)
            assertEquals(result, expected)
        }
    }

    @Test
    fun testCase1() {
        val key = "2b7e151628aed2a6abf7158809cf4f3c".hexToByteArray()
        val salt = "6bc1bee22e409f96e93d7e117393172a".hexToByteArray()
        val result = "070a16b46b4d4144f79bdd9dd04a287c".hexToByteArray()
        testCase(key, salt, result)
    }
}