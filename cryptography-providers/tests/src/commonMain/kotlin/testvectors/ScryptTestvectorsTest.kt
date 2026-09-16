/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.testvectors

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import kotlinx.coroutines.test.*
import kotlin.test.*

// RFC 7914 section 12. The N=1048576 vector is intentionally excluded from routine tests (~1 GiB).
abstract class ScryptTestvectorsTest(provider: CryptographyProvider) : AlgorithmTest<Scrypt>(Scrypt, provider) {

    private fun rfc7914TestCase(
        input: String,
        salt: String,
        cost: Int,
        blockSize: Int,
        parallelization: Int,
        outputHex: String,
    ): TestResult = testWithAlgorithm {
        val minimumMemoryBytes = 128L * blockSize * (cost + 2L * parallelization + 4L)
        val derivation = algorithm.secretDerivation(
            cost = cost,
            blockSize = blockSize,
            parallelization = parallelization,
            outputSize = 64.bytes,
            salt = salt.encodeToByteArray(),
            maximumMemoryBytes = minimumMemoryBytes,
        )
        assertEquals(outputHex, derivation.deriveSecretToByteArray(input.encodeToByteArray()).toHexString())
    }

    @Test
    fun rfc7914EmptyPasswordAndSalt() = rfc7914TestCase(
        input = "",
        salt = "",
        cost = 16,
        blockSize = 1,
        parallelization = 1,
        outputHex = "77d6576238657b203b19ca42c18a0497" +
                "f16b4844e3074ae8dfdffa3fede21442" +
                "fcd0069ded0948f8326a753a0fc81f17" +
                "e8d3e0fb2e0d3628cf35e20c38d18906",
    )

    @Test
    fun rfc7914PasswordAndNaCl() = rfc7914TestCase(
        input = "password",
        salt = "NaCl",
        cost = 1024,
        blockSize = 8,
        parallelization = 16,
        outputHex = "fdbabe1c9d3472007856e7190d01e9fe" +
                "7c6ad7cbc8237830e77376634b373162" +
                "2eaf30d92e22a3886ff109279d9830da" +
                "c727afb94a83ee6d8360cbdfa2cc0640",
    )

    @Test
    fun rfc7914PleaseLetMeInAndSodiumChloride() = rfc7914TestCase(
        input = "pleaseletmein",
        salt = "SodiumChloride",
        cost = 16384,
        blockSize = 8,
        parallelization = 1,
        outputHex = "7023bdcb3afd7348461c06cd81fd38eb" +
                "fda8fbba904f8e3ea9b543f6545da1f2" +
                "d5432955613f0fcf62d49705242a9af9" +
                "e61e85dc0d651e40dfcf017b45575887",
    )

}
