/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.testvectors

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import kotlin.test.*

/**
 * Test vectors for Poly1305.
 *
 * Sources:
 * - RFC 8439 Section 2.5.2 and Appendix A.3:
 *   https://datatracker.ietf.org/doc/html/rfc8439#section-2.5.2
 *   https://datatracker.ietf.org/doc/html/rfc8439#appendix-A.3
 * - BouncyCastle Poly1305Test (nacl-20110221 and BJA-620):
 *   https://github.com/bcgit/bc-java/blob/main/core/src/test/java/org/bouncycastle/crypto/test/Poly1305Test.java
 */
abstract class Poly1305TestvectorsTest(provider: CryptographyProvider) : AlgorithmTest<Poly1305>(Poly1305, provider) {

    private fun testCase(keyHex: String, dataHex: String, expectedTagHex: String) {
        testWithAlgorithm {
            val key = algorithm.keyDecoder().decodeFromByteArrayBlocking(
                format = Poly1305.Key.Format.RAW,
                bytes = keyHex.hexToByteArray()
            )
            val tag = key.signatureGenerator().generateSignatureBlocking(dataHex.hexToByteArray())
            assertEquals(expectedTagHex, tag.toHexString())
            assertTrue(key.signatureVerifier().tryVerifySignatureBlocking(dataHex.hexToByteArray(), tag))
        }
    }

    // RFC 8439 Section 2.5.2 - Poly1305 Test Vector
    @Test
    fun rfc8439Section252() = testCase(
        keyHex = "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
        dataHex = "43727970746f6772617068696320466f72756d2052657365617263682047726f7570",
        expectedTagHex = "a8061dc1305136c6c22b8baf0c0127a9"
    )

    // RFC 8439 Appendix A.3 #1 - All zeros
    @Test
    fun rfc8439AppendixA3tv1() = testCase(
        keyHex = "0000000000000000000000000000000000000000000000000000000000000000",
        dataHex = "00000000000000000000000000000000" +
            "00000000000000000000000000000000" +
            "00000000000000000000000000000000" +
            "00000000000000000000000000000000",
        expectedTagHex = "00000000000000000000000000000000"
    )

    // RFC 8439 Appendix A.3 #5 - r=2, s=0, message=0xFF*16
    // Tests: ((0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF + 2^128) * 2) mod (2^130-5) = 3
    @Test
    fun rfc8439AppendixA3tv5() = testCase(
        keyHex = "0200000000000000000000000000000000000000000000000000000000000000",
        dataHex = "ffffffffffffffffffffffffffffffff",
        expectedTagHex = "03000000000000000000000000000000"
    )

    // RFC 8439 Appendix A.3 #6 - r=2, s=0xFFFFFFFF..., message=0x02 padded
    @Test
    fun rfc8439AppendixA3tv6() = testCase(
        keyHex = "02000000000000000000000000000000ffffffffffffffffffffffffffffffff",
        dataHex = "02000000000000000000000000000000",
        expectedTagHex = "03000000000000000000000000000000"
    )

    // BouncyCastle nacl-20110221 test vector
    @Test
    fun bouncyCastleNacl() = testCase(
        keyHex = "eea6a7251c1e72916d11c2cb214d3c252539121d8e234e652d651fa4c8cff880",
        dataHex = "8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186a" +
            "c0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738" +
            "b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da" +
            "99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74" +
            "e355a5",
        expectedTagHex = "f3ffc7703f9400e52a7dfb4b3d3305d9"
    )

    // All 0xFF key and 256-byte all-0xFF message, verified with OpenSSL 3.x and Python cryptography
    @Test
    fun allFf256Bytes() = testCase(
        keyHex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        dataHex = "ffffffffffffffffffffffffffffffff".repeat(16),
        expectedTagHex = "c30c8c6a3af35fc6645a7e3a51df3f04"
    )
}
