/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.testvectors

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.providers.tests.*
import kotlin.test.*

/**
 * Test vectors for DH parameter encoding using RFC 3526 MODP groups.
 * See https://datatracker.ietf.org/doc/html/rfc3526
 *
 * These tests verify that DH parameters can be correctly decoded from DER format
 * and that the p and g values match the RFC specification.
 */
abstract class DhTestvectorsTest(provider: CryptographyProvider) : AlgorithmTest<DH>(DH, provider) {

    // RFC 3526 Section 3: 2048-bit MODP Group (Group 14)
    // p = 2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 }
    // g = 2
    @OptIn(ExperimentalStdlibApi::class)
    private val rfc3526Group14Der = (
            "308201080282010100ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e08" +
                    "8a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f143" +
                    "74fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386b" +
                    "fb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d" +
                    "39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c" +
                    "354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec0" +
                    "7a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015" +
                    "728e5a8aacaa68ffffffffffffffff020102"
            ).hexToByteArray()

    // RFC 3526 Group 14 p value as hex string (without leading zero)
    private val rfc3526Group14P = (
            "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e08" +
                    "8a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f143" +
                    "74fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386b" +
                    "fb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d" +
                    "39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c" +
                    "354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec0" +
                    "7a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015" +
                    "728e5a8aacaa68ffffffffffffffff"
            )

    @Test
    fun testRfc3526Group14ParameterDecoding() = testWithAlgorithm {
        val parameters = algorithm.parametersDecoder().decodeFromByteArray(
            DH.Parameters.Format.DER,
            rfc3526Group14Der
        )

        // Verify g = 2
        assertEquals(2, parameters.g.toInt(), "g should be 2")

        // Verify p matches RFC 3526 value
        @OptIn(ExperimentalStdlibApi::class)
        val pHex = parameters.p.encodeToByteArray()
            .let { bytes ->
                // Remove leading zero byte if present (sign byte)
                if (bytes.isNotEmpty() && bytes[0] == 0.toByte()) {
                    bytes.copyOfRange(1, bytes.size)
                } else {
                    bytes
                }
            }
            .toHexString()
        assertEquals(rfc3526Group14P, pHex, "p should match RFC 3526 Group 14 value")
    }

    @Test
    fun testRfc3526Group14ParameterEncodingRoundtrip() = testWithAlgorithm {
        val parameters = algorithm.parametersDecoder().decodeFromByteArray(
            DH.Parameters.Format.DER,
            rfc3526Group14Der
        )

        // Encode back to DER
        val encoded = parameters.encodeToByteArray(DH.Parameters.Format.DER)

        // Decode again
        val decoded = algorithm.parametersDecoder().decodeFromByteArray(
            DH.Parameters.Format.DER,
            encoded
        )

        // Verify values match
        assertEquals(parameters.p, decoded.p, "p should match after roundtrip")
        assertEquals(parameters.g, decoded.g, "g should match after roundtrip")
    }

    @Test
    fun testRfc3526Group14PemEncodingRoundtrip() = testWithAlgorithm {
        val parameters = algorithm.parametersDecoder().decodeFromByteArray(
            DH.Parameters.Format.DER,
            rfc3526Group14Der
        )

        // Encode to PEM
        val pem = parameters.encodeToByteArray(DH.Parameters.Format.PEM)

        // Verify PEM has correct label
        val pemString = pem.decodeToString()
        assertTrue(pemString.contains("-----BEGIN DH PARAMETERS-----"), "PEM should have correct begin label")
        assertTrue(pemString.contains("-----END DH PARAMETERS-----"), "PEM should have correct end label")

        // Decode from PEM
        val decoded = algorithm.parametersDecoder().decodeFromByteArray(
            DH.Parameters.Format.PEM,
            pem
        )

        // Verify values match
        assertEquals(parameters.p, decoded.p, "p should match after PEM roundtrip")
        assertEquals(parameters.g, decoded.g, "g should match after PEM roundtrip")
    }

    @Test
    fun testKeyGenerationWithRfc3526Group14() = testWithAlgorithm {
        val parameters = algorithm.parametersDecoder().decodeFromByteArray(
            DH.Parameters.Format.DER,
            rfc3526Group14Der
        )

        // Generate key pair
        val keyPair = parameters.keyPairGenerator().generate()

        // Verify public key y is in valid range: 1 < y < p-1
        val y = keyPair.publicKey.y
        assertTrue(y > 1.toBigInt(), "y should be greater than 1")
        assertTrue(y < parameters.p, "y should be less than p")

        // Verify private key x is in valid range: 1 < x < p-1
        val x = keyPair.privateKey.x
        assertTrue(x > 1.toBigInt(), "x should be greater than 1")
        assertTrue(x < parameters.p, "x should be less than p")

        // Verify key parameters match
        assertEquals(parameters.p, keyPair.publicKey.parameters.p, "Public key p should match")
        assertEquals(parameters.g, keyPair.publicKey.parameters.g, "Public key g should match")
        assertEquals(parameters.p, keyPair.privateKey.parameters.p, "Private key p should match")
        assertEquals(parameters.g, keyPair.privateKey.parameters.g, "Private key g should match")
    }

    @Test
    fun testSharedSecretSymmetry() = testWithAlgorithm {
        val parameters = algorithm.parametersDecoder().decodeFromByteArray(
            DH.Parameters.Format.DER,
            rfc3526Group14Der
        )

        // Generate two key pairs
        val keyPair1 = parameters.keyPairGenerator().generate()
        val keyPair2 = parameters.keyPairGenerator().generate()

        // Compute shared secrets both ways
        val secret1 = keyPair1.privateKey.sharedSecretGenerator()
            .generateSharedSecretToByteArray(keyPair2.publicKey)
        val secret2 = keyPair2.privateKey.sharedSecretGenerator()
            .generateSharedSecretToByteArray(keyPair1.publicKey)

        // Both should be equal
        assertContentEquals(secret1, secret2, "Shared secrets should match")

        // Shared secret size should be appropriate for 2048-bit DH
        // The shared secret should be at most 256 bytes (2048 bits)
        assertTrue(secret1.size <= 256, "Shared secret should be at most 256 bytes")
        assertTrue(secret1.size >= 200, "Shared secret should be at least 200 bytes for 2048-bit DH")
    }

    private fun Int.toBigInt() = this.toLong().toBigInt()
}
