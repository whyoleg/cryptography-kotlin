package dev.whyoleg.cryptography.providers.tests.testvectors

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.algorithms.AES.*

import dev.whyoleg.cryptography.providers.tests.api.*
import kotlin.test.*

abstract class AesCmacTestvectorsTest(provider: CryptographyProvider) : AlgorithmTest<AES.CMAC>(AES.CMAC, provider) {

    private fun testCase(key: ByteArray, salt: ByteArray, expected: ByteArray) {
        testWithAlgorithm {
            val key = algorithm.keyDecoder().decodeFromByteArrayBlocking(format = Key.Format.RAW, bytes = key)
            val result = key.signatureGenerator().createSignFunction()
                .apply { update(salt) }
                .signToByteArray()
            assertEquals(16, result.size)
            assertEquals(result.toHexString(), expected.toHexString())
        }
    }

    @Test
    fun testDiversifyKeyCase1() {
        val key = "2b7e151628aed2a6abf7158809cf4f3c".hexToByteArray()
        val salt = "6bc1bee22e409f96e93d7e117393172a".hexToByteArray()
        val result = "070a16b46b4d4144f79bdd9dd04a287c".hexToByteArray()
        testCase(key, salt, result)
    }

    @Test
    fun testDiversifyKeyCase2() {
        val key = "2b7e151628aed2a6abf7158809cf4f3c".hexToByteArray()
        val salt = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411".hexToByteArray()
        val result = "dfa66747de9ae63030ca32611497c827".hexToByteArray()
        testCase(key, salt, result)
    }

    @Test
    fun testDiversifyKeyCase3() {
        val key = "2b7e151628aed2a6abf7158809cf4f3c".hexToByteArray()
        val salt = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411".hexToByteArray()
        val result = "dfa66747de9ae63030ca32611497c827".hexToByteArray()
        testCase(key, salt, result)
    }

    @Test
    fun testDiversifyKeyCase4() {
        val key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4".hexToByteArray()
        val salt = "".hexToByteArray()
        val result = "028962f61b7bf89efc6b551f4667d983".hexToByteArray()
        testCase(key, salt, result)
    }
}