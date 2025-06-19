/*
 * Copyright (c) 2024-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.default

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.api.*
import dev.whyoleg.cryptography.random.*
import kotlinx.io.bytestring.*
import kotlin.test.*

private const val ivSize = 16

abstract class AesCtrTest(provider: CryptographyProvider) : AesBasedTest<AES.CTR>(AES.CTR, provider) {
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
