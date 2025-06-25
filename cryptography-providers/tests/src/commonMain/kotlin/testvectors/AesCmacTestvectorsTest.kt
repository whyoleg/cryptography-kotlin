/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.testvectors

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.AES.*
import dev.whyoleg.cryptography.providers.tests.*
import kotlin.test.*

/**
 * Vector test for AES-CMAC algorithm found in:
 * https://datatracker.ietf.org/doc/html/rfc5297
 * https://github.com/aead/cmac/blob/master/vectors_test.go
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core_All.pdf
 */
abstract class AesCmacTestvectorsTest(provider: CryptographyProvider) : AlgorithmTest<CMAC>(CMAC, provider) {

    private fun testCase(key: String, salt: String, expected: String) {
        testWithAlgorithm {
            val key = algorithm.keyDecoder().decodeFromByteArrayBlocking(format = Key.Format.RAW, bytes = key.hexToByteArray())
            val result = key.signatureGenerator().createSignFunction()
                .apply { update(salt.hexToByteArray()) }
                .signToByteArray()
            assertEquals(16, result.size)
            assertEquals(result.toHexString(), expected)
        }
    }

    @Test
    fun testDiversifyKeyCase1() {
        val key = "2b7e151628aed2a6abf7158809cf4f3c"
        val salt = "6bc1bee22e409f96e93d7e117393172a"
        val result = "070a16b46b4d4144f79bdd9dd04a287c"
        testCase(key, salt, result)
    }

    @Test
    fun testDiversifyKeyCase2() {
        val key = "2b7e151628aed2a6abf7158809cf4f3c"
        val salt = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411"
        val result = "dfa66747de9ae63030ca32611497c827"
        testCase(key, salt, result)
    }

    @Test
    fun testDiversifyKeyCase3() {
        val key = "2b7e151628aed2a6abf7158809cf4f3c"
        val salt = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411"
        val result = "dfa66747de9ae63030ca32611497c827"
        testCase(key, salt, result)
    }

    @Test
    fun testDiversifyKeyCase4() {
        val key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
        val salt = ""
        val result = "028962f61b7bf89efc6b551f4667d983"
        testCase(key, salt, result)
    }
}