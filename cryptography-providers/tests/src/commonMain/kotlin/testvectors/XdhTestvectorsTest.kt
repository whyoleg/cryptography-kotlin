/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.testvectors

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import kotlinx.coroutines.test.*
import kotlin.test.*

// See https://datatracker.ietf.org/doc/html/rfc7748
abstract class XdhTestvectorsTest(provider: CryptographyProvider) : AlgorithmTest<XDH>(XDH, provider) {

    /**
     * Basic functional test from RFC 7748 Section 5.2
     * Tests scalar multiplication: privateKey * publicKey = sharedSecret
     */
    private fun rfc7748testCase(
        curve: XDH.Curve,
        privateKeyHex: String,
        publicKeyHex: String,
        expectedSharedSecretHex: String,
    ): TestResult = testWithAlgorithm {
        if (!supportsCurve(curve)) return@testWithAlgorithm

        val privateKey = algorithm.privateKeyDecoder(curve)
            .decodeFromByteArray(XDH.PrivateKey.Format.RAW, privateKeyHex.hexToByteArray())

        val publicKey = algorithm.publicKeyDecoder(curve)
            .decodeFromByteArray(XDH.PublicKey.Format.RAW, publicKeyHex.hexToByteArray())

        val sharedSecret = privateKey.sharedSecretGenerator()
            .generateSharedSecretToByteArray(publicKey)

        assertEquals(expectedSharedSecretHex, sharedSecret.toHexString(), "Shared secret mismatch for $curve")
    }

    /**
     * Diffie-Hellman test from RFC 7748 Sections 6.1 and 6.2
     * Tests full key exchange between Alice and Bob
     */
    private fun rfc7748DiffieHellmanTest(
        curve: XDH.Curve,
        alicePrivateHex: String,
        alicePublicHex: String,
        bobPrivateHex: String,
        bobPublicHex: String,
        expectedSharedSecretHex: String,
    ): TestResult = testWithAlgorithm {
        if (!supportsCurve(curve)) return@testWithAlgorithm

        val privateKeyDecoder = algorithm.privateKeyDecoder(curve)
        val publicKeyDecoder = algorithm.publicKeyDecoder(curve)

        // Decode Alice's keys
        val alicePrivate = privateKeyDecoder.decodeFromByteArray(
            XDH.PrivateKey.Format.RAW,
            alicePrivateHex.hexToByteArray()
        )
        val alicePublic = publicKeyDecoder.decodeFromByteArray(
            XDH.PublicKey.Format.RAW,
            alicePublicHex.hexToByteArray()
        )

        // Decode Bob's keys
        val bobPrivate = privateKeyDecoder.decodeFromByteArray(
            XDH.PrivateKey.Format.RAW,
            bobPrivateHex.hexToByteArray()
        )
        val bobPublic = publicKeyDecoder.decodeFromByteArray(
            XDH.PublicKey.Format.RAW,
            bobPublicHex.hexToByteArray()
        )

        // Compute shared secrets
        val sharedSecretAliceBob = alicePrivate.sharedSecretGenerator()
            .generateSharedSecretToByteArray(bobPublic)

        val sharedSecretBobAlice = bobPrivate.sharedSecretGenerator()
            .generateSharedSecretToByteArray(alicePublic)

        // Verify both produce the same shared secret
        assertContentEquals(
            sharedSecretAliceBob,
            sharedSecretBobAlice,
            "Alice and Bob should compute the same shared secret"
        )

        // Verify against expected value
        assertEquals(
            expectedSharedSecretHex,
            sharedSecretAliceBob.toHexString(),
            "Shared secret should match RFC 7748 test vector for $curve"
        )
    }

    // Section 5.2: Basic Functional Tests

    @Test
    fun rfc7748Section52_X25519_Test1() = rfc7748testCase(
        curve = XDH.Curve.X25519,
        privateKeyHex = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        publicKeyHex = "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        expectedSharedSecretHex = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
    )

    @Test
    fun rfc7748Section52_X25519_Test2() = rfc7748testCase(
        curve = XDH.Curve.X25519,
        privateKeyHex = "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
        publicKeyHex = "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
        expectedSharedSecretHex = "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"
    )

    @Test
    fun rfc7748Section52_X448_Test1() = rfc7748testCase(
        curve = XDH.Curve.X448,
        privateKeyHex = "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3",
        publicKeyHex = "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086",
        expectedSharedSecretHex = "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f"
    )

    @Test
    fun rfc7748Section52_X448_Test2() = rfc7748testCase(
        curve = XDH.Curve.X448,
        privateKeyHex = "203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f",
        publicKeyHex = "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db",
        expectedSharedSecretHex = "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d"
    )

    // Section 6.1: X25519 Diffie-Hellman

    @Test
    fun rfc7748Section61_X25519_DiffieHellman() = rfc7748DiffieHellmanTest(
        curve = XDH.Curve.X25519,
        alicePrivateHex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        alicePublicHex = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        bobPrivateHex = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        bobPublicHex = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        expectedSharedSecretHex = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    )

    // Section 6.2: X448 Diffie-Hellman

    @Test
    fun rfc7748Section62_X448_DiffieHellman() = rfc7748DiffieHellmanTest(
        curve = XDH.Curve.X448,
        alicePrivateHex = "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
        alicePublicHex = "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0",
        bobPrivateHex = "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d",
        bobPublicHex = "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609",
        expectedSharedSecretHex = "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d"
    )
}
