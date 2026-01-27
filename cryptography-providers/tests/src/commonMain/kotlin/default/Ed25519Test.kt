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

    @Test
    fun testDeterministicSignatures() = testWithAlgorithm {
        // ED25519 signatures are deterministic - same key + same data = same signature
        val keyPair = algorithm.keyPairGenerator().generateKey()
        val signatureGenerator = keyPair.privateKey.signatureGenerator()

        val data = CryptographyRandom.nextBytes(100)

        val signature1 = signatureGenerator.generateSignature(data)
        val signature2 = signatureGenerator.generateSignature(data)

        assertContentEquals(
            signature1,
            signature2,
            "ED25519 signatures should be deterministic"
        )
    }
}
