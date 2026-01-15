/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.default

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.providers.tests.*
import kotlin.test.*

// RFC 3526 MODP Group 14 (2048-bit) parameters for testing
private val testP = (
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
                "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
                "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
                "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
                "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
                "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
                "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
                "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
                "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
                "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
                "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
        ).toBigInt(16)

private val testG = 2.toBigInt()

private fun String.toBigInt(radix: Int): BigInt {
    // Convert hex string to BigInt via ByteArray
    require(radix == 16) { "Only radix 16 is supported" }
    // Prepend 00 to ensure positive interpretation in two's complement
    val hex = "00" + (if (length % 2 == 0) this else "0$this")
    val bytes = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    return bytes.decodeToBigInt()
}

abstract class DhTest(provider: CryptographyProvider) : AlgorithmTest<DH>(DH, provider) {

    private val testParameters = DH.Parameters(testP, testG)

    @Test
    fun testKeyGeneration() = testWithAlgorithm {
        val keyPair = algorithm.keyPairGenerator(testParameters).generateKey()
        assertNotNull(keyPair.publicKey)
        assertNotNull(keyPair.privateKey)
    }

    @Test
    fun testSharedSecretGeneration() = testWithAlgorithm {
        val keyPair1 = algorithm.keyPairGenerator(testParameters).generateKey()
        val keyPair2 = algorithm.keyPairGenerator(testParameters).generateKey()

        // Both parties should derive the same shared secret
        val secret1 = keyPair1.privateKey.sharedSecretGenerator().generateSharedSecretToByteArray(keyPair2.publicKey)
        val secret2 = keyPair2.privateKey.sharedSecretGenerator().generateSharedSecretToByteArray(keyPair1.publicKey)

        assertContentEquals(secret1, secret2, "Shared secrets should match")

        // Also test reverse direction (public + private)
        val secret3 = keyPair1.publicKey.sharedSecretGenerator().generateSharedSecretToByteArray(keyPair2.privateKey)
        val secret4 = keyPair2.publicKey.sharedSecretGenerator().generateSharedSecretToByteArray(keyPair1.privateKey)

        assertContentEquals(secret1, secret3, "Shared secrets (reverse 1) should match")
        assertContentEquals(secret1, secret4, "Shared secrets (reverse 2) should match")
    }

    @Test
    fun testKeyEncodingDer() = testWithAlgorithm {
        val keyPair = algorithm.keyPairGenerator(testParameters).generateKey()

        // Test public key DER encoding roundtrip
        val publicDer = keyPair.publicKey.encodeToByteArray(DH.PublicKey.Format.DER)
        val decodedPublic = algorithm.publicKeyDecoder(testParameters).decodeFromByteArray(DH.PublicKey.Format.DER, publicDer)

        // Test private key DER encoding roundtrip
        val privateDer = keyPair.privateKey.encodeToByteArray(DH.PrivateKey.Format.DER)
        val decodedPrivate = algorithm.privateKeyDecoder(testParameters).decodeFromByteArray(DH.PrivateKey.Format.DER, privateDer)

        // Verify decoded keys work for shared secret generation
        val originalSecret = keyPair.privateKey.sharedSecretGenerator().generateSharedSecretToByteArray(keyPair.publicKey)
        val decodedSecret = decodedPrivate.sharedSecretGenerator().generateSharedSecretToByteArray(decodedPublic)
        assertContentEquals(originalSecret, decodedSecret, "Decoded keys should produce same shared secret")
    }

    @Test
    fun testKeyEncodingPem() = testWithAlgorithm {
        val keyPair = algorithm.keyPairGenerator(testParameters).generateKey()

        // Test public key PEM encoding roundtrip
        val publicPem = keyPair.publicKey.encodeToByteArray(DH.PublicKey.Format.PEM)
        val decodedPublic = algorithm.publicKeyDecoder(testParameters).decodeFromByteArray(DH.PublicKey.Format.PEM, publicPem)

        // Test private key PEM encoding roundtrip
        val privatePem = keyPair.privateKey.encodeToByteArray(DH.PrivateKey.Format.PEM)
        val decodedPrivate = algorithm.privateKeyDecoder(testParameters).decodeFromByteArray(DH.PrivateKey.Format.PEM, privatePem)

        // Verify decoded keys work for shared secret generation
        val originalSecret = keyPair.privateKey.sharedSecretGenerator().generateSharedSecretToByteArray(keyPair.publicKey)
        val decodedSecret = decodedPrivate.sharedSecretGenerator().generateSharedSecretToByteArray(decodedPublic)
        assertContentEquals(originalSecret, decodedSecret, "Decoded keys should produce same shared secret")
    }

    @Test
    fun testKeyEncodingRaw() = testWithAlgorithm {
        if (!supportsKeyFormat(DH.PublicKey.Format.RAW)) return@testWithAlgorithm
        if (!supportsKeyFormat(DH.PrivateKey.Format.RAW)) return@testWithAlgorithm

        val keyPair = algorithm.keyPairGenerator(testParameters).generateKey()

        // Test public key RAW encoding roundtrip
        val publicRaw = keyPair.publicKey.encodeToByteArray(DH.PublicKey.Format.RAW)
        val decodedPublic = algorithm.publicKeyDecoder(testParameters).decodeFromByteArray(DH.PublicKey.Format.RAW, publicRaw)

        // Test private key RAW encoding roundtrip
        val privateRaw = keyPair.privateKey.encodeToByteArray(DH.PrivateKey.Format.RAW)
        val decodedPrivate = algorithm.privateKeyDecoder(testParameters).decodeFromByteArray(DH.PrivateKey.Format.RAW, privateRaw)

        // Verify decoded keys work for shared secret generation
        val originalSecret = keyPair.privateKey.sharedSecretGenerator().generateSharedSecretToByteArray(keyPair.publicKey)

        // Test each key separately to isolate which decode might be broken
        val secretWithDecodedPublic = keyPair.privateKey.sharedSecretGenerator().generateSharedSecretToByteArray(decodedPublic)
        assertContentEquals(originalSecret, secretWithDecodedPublic, "Public key RAW decode should work")

        val secretWithDecodedPrivate = decodedPrivate.sharedSecretGenerator().generateSharedSecretToByteArray(keyPair.publicKey)
        assertContentEquals(originalSecret, secretWithDecodedPrivate, "Private key RAW decode should work")

        val decodedSecret = decodedPrivate.sharedSecretGenerator().generateSharedSecretToByteArray(decodedPublic)
        assertContentEquals(originalSecret, decodedSecret, "Decoded keys should produce same shared secret")
    }
}
