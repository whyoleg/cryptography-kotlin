/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.testvectors

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import kotlin.test.*

/**
 * Test vectors for ChaCha20.
 *
 * Sources:
 * - RFC 8439 Section 2.4.2 and Appendix A.2:
 *   https://datatracker.ietf.org/doc/html/rfc8439#section-2.4.2
 *   https://datatracker.ietf.org/doc/html/rfc8439#appendix-A.2
 * - pyca/cryptography RFC 7539 test vectors:
 *   https://github.com/pyca/cryptography/pull/3918
 *
 * Note: Our implementation uses initial counter=1 (matching RFC 8439 Section 2.4),
 * so only test vectors with counter=1 are directly usable.
 */
abstract class ChaCha20TestvectorsTest(provider: CryptographyProvider) : AlgorithmTest<ChaCha20>(ChaCha20, provider) {

    private fun testCase(keyHex: String, nonceHex: String, plaintextHex: String, ciphertextHex: String) {
        testWithAlgorithm {
            val key = algorithm.keyDecoder().decodeFromByteArrayBlocking(
                format = ChaCha20.Key.Format.RAW,
                bytes = keyHex.hexToByteArray()
            )
            val cipher = key.cipher()
            val nonce = nonceHex.hexToByteArray()
            val plaintext = plaintextHex.hexToByteArray()

            val encrypted = cipher.encryptWithIvBlocking(nonce, plaintext)
            assertEquals(ciphertextHex, encrypted.toHexString())

            val decrypted = cipher.decryptWithIvBlocking(nonce, encrypted)
            assertEquals(plaintextHex, decrypted.toHexString())
        }
    }

    // RFC 8439 Section 2.4.2 - "Sunscreen" test vector (counter=1)
    @Test
    fun rfc8439Section242() = testCase(
        keyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        nonceHex = "000000000000004a00000000",
        plaintextHex = "4c616469657320616e642047656e746c656d656e206f662074686520636c6173" +
            "73206f66202739393a204966204920636f756c64206f6666657220796f75206f" +
            "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73" +
            "637265656e20776f756c642062652069742e",
        ciphertextHex = "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b" +
            "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8" +
            "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736" +
            "5af90bbf74a35be6b40b8eedf2785e42874d"
    )

    // RFC 8439 Appendix A.2 #2 - IETF Contribution text (counter=1)
    // Uses IETF 96-bit nonce; produces same keystream as DJB variant for this specific nonce.
    @Test
    fun rfc8439AppendixA2tv2() = testCase(
        keyHex = "0000000000000000000000000000000000000000000000000000000000000001",
        nonceHex = "000000000000000000000002",
        plaintextHex = "416e79207375626d697373696f6e20746f20746865204945544620696e74656e" +
            "6465642062792074686520436f6e7472696275746f7220666f72207075626c69" +
            "636174696f6e20617320616c6c206f722070617274206f6620616e2049455446" +
            "20496e7465726e65742d4472616674206f722052464320616e6420616e792073" +
            "746174656d656e74206d6164652077697468696e2074686520636f6e74657874" +
            "206f6620616e204945544620616374697669747920697320636f6e7369646572" +
            "656420616e20224945544620436f6e747269627574696f6e222e205375636820" +
            "73746174656d656e747320696e636c756465206f72616c2073746174656d656e" +
            "747320696e20494554462073657373696f6e732c2061732077656c6c20617320" +
            "7772697474656e20616e6420656c656374726f6e696320636f6d6d756e696361" +
            "74696f6e73206d61646520617420616e792074696d65206f7220706c6163652c" +
            "20776869636820617265206164647265737365642074" +
            "6f",
        ciphertextHex = "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec" +
            "2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d" +
            "4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e527950" +
            "42bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85a" +
            "d00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259d" +
            "c4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b" +
            "0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6c" +
            "cc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0b" +
            "c39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f" +
            "5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e6" +
            "98ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab" +
            "7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f22" +
            "1"
    )
}
