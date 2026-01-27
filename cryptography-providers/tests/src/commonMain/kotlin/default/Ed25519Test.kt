/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.default

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import dev.whyoleg.cryptography.random.*
import kotlinx.io.bytestring.*
import kotlin.math.*
import kotlin.test.*

abstract class Ed25519Test(provider: CryptographyProvider) : AlgorithmTest<ED25519>(ED25519, provider), SignatureTest {

    // ED25519 key and signature sizes (all in bytes)
    private val publicKeyRawSize = 32
    private val privateKeyRawSize = 32
    private val signatureSize = 64

    // DER sizes
    private val publicKeyDerSize = 44 // SubjectPublicKeyInfo overhead
    private val privateKeyDerSizeMin = 48 // PrivateKeyInfo without public key
    private val privateKeyDerSizeMax = 85 // PrivateKeyInfo with public key (varies by implementation)

    @Test
    fun testKeySizes() = testWithAlgorithm {
        val keyPair = algorithm.keyPairGenerator().generateKey()

        // Public key sizes
        assertEquals(
            expected = publicKeyRawSize,
            actual = keyPair.publicKey.encodeToByteString(ED25519.PublicKey.Format.RAW).size,
            message = "Public key RAW size mismatch"
        )
        assertEquals(
            expected = publicKeyDerSize,
            actual = keyPair.publicKey.encodeToByteString(ED25519.PublicKey.Format.DER).size,
            message = "Public key DER size mismatch"
        )

        // Private key sizes
        assertEquals(
            expected = privateKeyRawSize,
            actual = keyPair.privateKey.encodeToByteString(ED25519.PrivateKey.Format.RAW).size,
            message = "Private key RAW size mismatch"
        )
        val privateKeyDerSize = keyPair.privateKey.encodeToByteString(ED25519.PrivateKey.Format.DER).size
        assertTrue(
            privateKeyDerSize in privateKeyDerSizeMin..privateKeyDerSizeMax,
            "Private key DER size $privateKeyDerSize not in expected range $privateKeyDerSizeMin..$privateKeyDerSizeMax"
        )
    }

    @Test
    fun testSignatureSizes() = testWithAlgorithm {
        val keyPair = algorithm.keyPairGenerator().generateKey()
        val signatureGenerator = keyPair.privateKey.signatureGenerator()

        // Empty data
        assertEquals(
            signatureSize,
            signatureGenerator.generateSignature(ByteArray(0)).size,
            "Signature size mismatch for empty data"
        )

        // Various data sizes
        repeat(8) { n ->
            val size = 10.0.pow(n).toInt()
            val data = CryptographyRandom.nextBytes(size)
            assertEquals(
                signatureSize,
                signatureGenerator.generateSignature(data).size,
                "Signature size mismatch for data size $size"
            )
        }
    }

    @Test
    fun testSignAndVerify() = testWithAlgorithm {
        val keyPair = algorithm.keyPairGenerator().generateKey()
        val signatureGenerator = keyPair.privateKey.signatureGenerator()
        val signatureVerifier = keyPair.publicKey.signatureVerifier()

        // Sign and verify various data sizes
        repeat(8) { n ->
            val size = 10.0.pow(n).toInt()
            val data = CryptographyRandom.nextBytes(size)
            val signature = signatureGenerator.generateSignature(data)

            assertTrue(
                signatureVerifier.tryVerifySignature(data, signature),
                "Signature verification failed for data size $size"
            )
        }
    }

    @Test
    fun testVerifyWrongKey() = testWithAlgorithm {
        val keyPair1 = algorithm.keyPairGenerator().generateKey()
        val keyPair2 = algorithm.keyPairGenerator().generateKey()

        val data = CryptographyRandom.nextBytes(100)
        val signature = keyPair1.privateKey.signatureGenerator().generateSignature(data)

        // Verification with wrong key should fail
        assertFalse(
            keyPair2.publicKey.signatureVerifier().tryVerifySignature(data, signature),
            "Signature verification should fail with wrong key"
        )
    }

    @Test
    fun testVerifyWrongData() = testWithAlgorithm {
        val keyPair = algorithm.keyPairGenerator().generateKey()

        val data = CryptographyRandom.nextBytes(100)
        val signature = keyPair.privateKey.signatureGenerator().generateSignature(data)

        // Verification with modified data should fail
        val modifiedData = data.copyOf().also { it[0] = (it[0].toInt() xor 0xFF).toByte() }
        assertFalse(
            keyPair.publicKey.signatureVerifier().tryVerifySignature(modifiedData, signature),
            "Signature verification should fail with modified data"
        )
    }

    @Test
    fun testVerifyWrongSignature() = testWithAlgorithm {
        val keyPair = algorithm.keyPairGenerator().generateKey()

        val data = CryptographyRandom.nextBytes(100)
        val signature = keyPair.privateKey.signatureGenerator().generateSignature(data)

        // Verification with modified signature should fail
        // Modify the 's' scalar (bytes 32+) rather than the 'R' point (bytes 0-31)
        // to avoid creating an invalid curve point which may cause exceptions
        val modifiedSignature = signature.copyOf().also { it[32] = (it[32].toInt() xor 0xFF).toByte() }
        assertFalse(
            keyPair.publicKey.signatureVerifier().tryVerifySignature(data, modifiedSignature),
            "Signature verification should fail with modified signature"
        )
    }

    @Test
    fun testPublicKeyRoundTrip() = testWithAlgorithm {
        val keyPair = algorithm.keyPairGenerator().generateKey()
        val publicKeyDecoder = algorithm.publicKeyDecoder()

        // RAW format round-trip
        val rawBytes = keyPair.publicKey.encodeToByteString(ED25519.PublicKey.Format.RAW)
        val decodedRaw = publicKeyDecoder.decodeFromByteString(ED25519.PublicKey.Format.RAW, rawBytes)
        assertContentEquals(
            rawBytes,
            decodedRaw.encodeToByteString(ED25519.PublicKey.Format.RAW),
            "Public key RAW round-trip failed"
        )

        // DER format round-trip
        val derBytes = keyPair.publicKey.encodeToByteString(ED25519.PublicKey.Format.DER)
        val decodedDer = publicKeyDecoder.decodeFromByteString(ED25519.PublicKey.Format.DER, derBytes)
        assertContentEquals(
            derBytes,
            decodedDer.encodeToByteString(ED25519.PublicKey.Format.DER),
            "Public key DER round-trip failed"
        )

        // PEM format round-trip
        val pemBytes = keyPair.publicKey.encodeToByteString(ED25519.PublicKey.Format.PEM)
        val decodedPem = publicKeyDecoder.decodeFromByteString(ED25519.PublicKey.Format.PEM, pemBytes)
        assertContentEquals(
            derBytes,
            decodedPem.encodeToByteString(ED25519.PublicKey.Format.DER),
            "Public key PEM round-trip failed"
        )
    }

    @Test
    fun testPrivateKeyRoundTrip() = testWithAlgorithm {
        val keyPair = algorithm.keyPairGenerator().generateKey()
        val privateKeyDecoder = algorithm.privateKeyDecoder()

        // RAW format round-trip
        val rawBytes = keyPair.privateKey.encodeToByteString(ED25519.PrivateKey.Format.RAW)
        val decodedRaw = privateKeyDecoder.decodeFromByteString(ED25519.PrivateKey.Format.RAW, rawBytes)
        assertContentEquals(
            rawBytes,
            decodedRaw.encodeToByteString(ED25519.PrivateKey.Format.RAW),
            "Private key RAW round-trip failed"
        )

        // DER format round-trip
        val derBytes = keyPair.privateKey.encodeToByteString(ED25519.PrivateKey.Format.DER)
        val decodedDer = privateKeyDecoder.decodeFromByteString(ED25519.PrivateKey.Format.DER, derBytes)
        // Compare RAW to avoid DER encoding differences (publicKey presence)
        assertContentEquals(
            rawBytes,
            decodedDer.encodeToByteString(ED25519.PrivateKey.Format.RAW),
            "Private key DER round-trip failed"
        )

        // PEM format round-trip
        val pemBytes = keyPair.privateKey.encodeToByteString(ED25519.PrivateKey.Format.PEM)
        val decodedPem = privateKeyDecoder.decodeFromByteString(ED25519.PrivateKey.Format.PEM, pemBytes)
        assertContentEquals(
            rawBytes,
            decodedPem.encodeToByteString(ED25519.PrivateKey.Format.RAW),
            "Private key PEM round-trip failed"
        )
    }

    @Test
    fun testDecodedKeyCanSign() = testWithAlgorithm {
        val keyPair = algorithm.keyPairGenerator().generateKey()
        val privateKeyDecoder = algorithm.privateKeyDecoder()
        val publicKeyDecoder = algorithm.publicKeyDecoder()

        // Decode keys from RAW format
        val rawPrivateKey = keyPair.privateKey.encodeToByteString(ED25519.PrivateKey.Format.RAW)
        val rawPublicKey = keyPair.publicKey.encodeToByteString(ED25519.PublicKey.Format.RAW)

        val decodedPrivateKey = privateKeyDecoder.decodeFromByteString(ED25519.PrivateKey.Format.RAW, rawPrivateKey)
        val decodedPublicKey = publicKeyDecoder.decodeFromByteString(ED25519.PublicKey.Format.RAW, rawPublicKey)

        // Sign with decoded private key
        val data = CryptographyRandom.nextBytes(100)
        val signature = decodedPrivateKey.signatureGenerator().generateSignature(data)

        // Verify with decoded public key
        assertTrue(
            decodedPublicKey.signatureVerifier().tryVerifySignature(data, signature),
            "Decoded key signature verification failed"
        )

        // Also verify with original public key
        assertTrue(
            keyPair.publicKey.signatureVerifier().tryVerifySignature(data, signature),
            "Original key signature verification of decoded key signature failed"
        )
    }

    @Test
    fun testPublicKeyFromPrivateKey() = testWithAlgorithm {
        val keyPair = algorithm.keyPairGenerator().generateKey()

        // Get public key from private key
        val derivedPublicKey = keyPair.privateKey.getPublicKey()

        // Compare with original public key
        assertContentEquals(
            keyPair.publicKey.encodeToByteString(ED25519.PublicKey.Format.RAW),
            derivedPublicKey.encodeToByteString(ED25519.PublicKey.Format.RAW),
            "Derived public key doesn't match original"
        )
    }

    @Test
    fun testFunctions() = testWithAlgorithm {
        if (!supportsFunctions()) {
            logger.log { "Skipping function test because functions are not supported by provider" }
            return@testWithAlgorithm
        }

        val keyPair = algorithm.keyPairGenerator().generateKey()
        val signatureGenerator = keyPair.privateKey.signatureGenerator()
        val signatureVerifier = keyPair.publicKey.signatureVerifier()

        repeat(10) {
            val size = CryptographyRandom.nextInt(1024, 20000)
            val data = ByteString(CryptographyRandom.nextBytes(size))
            assertSignaturesViaFunction(signatureGenerator, signatureVerifier, data)
        }
    }

    // RFC 8032 Section 7.1 Test Vectors
    // https://datatracker.ietf.org/doc/html/rfc8032#section-7.1
    private data class Ed25519TestVector(
        val privateKey: String,  // hex, 32 bytes seed
        val publicKey: String,   // hex, 32 bytes
        val message: String,     // hex
        val signature: String,   // hex, 64 bytes
    )

    private val testVectors = listOf(
        // TEST 1 (empty message)
        Ed25519TestVector(
            privateKey = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            publicKey = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            message = "",
            signature = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ),
        // TEST 2 (1 byte message: 0x72)
        Ed25519TestVector(
            privateKey = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            publicKey = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            message = "72",
            signature = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        ),
        // TEST 3 (2 byte message)
        Ed25519TestVector(
            privateKey = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            publicKey = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            message = "af82",
            signature = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
        ),
    )

    @OptIn(ExperimentalStdlibApi::class)
    @Test
    fun testRfc8032Verification() = testWithAlgorithm {
        // Test that we can verify signatures from RFC 8032 test vectors
        val publicKeyDecoder = algorithm.publicKeyDecoder()

        for ((index, vector) in testVectors.withIndex()) {
            val publicKey = publicKeyDecoder.decodeFromByteArray(
                ED25519.PublicKey.Format.RAW,
                vector.publicKey.hexToByteArray()
            )
            val message = vector.message.hexToByteArray()
            val signature = vector.signature.hexToByteArray()

            assertTrue(
                publicKey.signatureVerifier().tryVerifySignature(message, signature),
                "RFC 8032 test vector ${index + 1} verification failed"
            )
        }
    }

    @OptIn(ExperimentalStdlibApi::class)
    @Test
    fun testRfc8032SignatureVerifiable() = testWithAlgorithm {
        // Test that signatures we generate are verifiable with RFC 8032 keys
        val privateKeyDecoder = algorithm.privateKeyDecoder()
        val publicKeyDecoder = algorithm.publicKeyDecoder()

        for ((index, vector) in testVectors.withIndex()) {
            val privateKey = privateKeyDecoder.decodeFromByteArray(
                ED25519.PrivateKey.Format.RAW,
                vector.privateKey.hexToByteArray()
            )
            // Decode public key separately from vector (don't rely on getPublicKey)
            val publicKey = publicKeyDecoder.decodeFromByteArray(
                ED25519.PublicKey.Format.RAW,
                vector.publicKey.hexToByteArray()
            )
            val message = vector.message.hexToByteArray()

            // Generate signature (may differ from RFC due to randomization)
            val signature = privateKey.signatureGenerator().generateSignature(message)

            // But it must be verifiable
            assertTrue(
                publicKey.signatureVerifier().tryVerifySignature(message, signature),
                "RFC 8032 test vector ${index + 1} generated signature not verifiable"
            )
        }
    }
}
