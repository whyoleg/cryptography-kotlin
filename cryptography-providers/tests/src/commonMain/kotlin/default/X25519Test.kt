/*
 * Copyright (c) 2025-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.default

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import dev.whyoleg.cryptography.random.*
import kotlinx.io.bytestring.*
import kotlin.test.*

abstract class X25519Test(provider: CryptographyProvider) : AlgorithmTest<X25519>(X25519, provider) {

    // X25519 key sizes (all in bytes)
    private val publicKeyRawSize = 32
    private val privateKeyRawSize = 32
    private val sharedSecretSize = 32

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
            actual = keyPair.publicKey.encodeToByteString(X25519.PublicKey.Format.RAW).size,
            message = "Public key RAW size mismatch"
        )
        assertEquals(
            expected = publicKeyDerSize,
            actual = keyPair.publicKey.encodeToByteString(X25519.PublicKey.Format.DER).size,
            message = "Public key DER size mismatch"
        )

        // Private key sizes
        assertEquals(
            expected = privateKeyRawSize,
            actual = keyPair.privateKey.encodeToByteString(X25519.PrivateKey.Format.RAW).size,
            message = "Private key RAW size mismatch"
        )
        val privateKeyDerSize = keyPair.privateKey.encodeToByteString(X25519.PrivateKey.Format.DER).size
        assertTrue(
            privateKeyDerSize in privateKeyDerSizeMin..privateKeyDerSizeMax,
            "Private key DER size $privateKeyDerSize not in expected range $privateKeyDerSizeMin..$privateKeyDerSizeMax"
        )
    }

    @Test
    fun testSharedSecretSize() = testWithAlgorithm {
        val keyPair1 = algorithm.keyPairGenerator().generateKey()
        val keyPair2 = algorithm.keyPairGenerator().generateKey()

        val sharedSecret = keyPair1.privateKey.sharedSecretGenerator()
            .generateSharedSecret(keyPair2.publicKey)

        assertEquals(
            expected = sharedSecretSize,
            actual = sharedSecret.size,
            message = "Shared secret size mismatch"
        )
    }

    @Test
    fun testKeyAgreement() = testWithAlgorithm {
        val keyPair1 = algorithm.keyPairGenerator().generateKey()
        val keyPair2 = algorithm.keyPairGenerator().generateKey()

        // Both parties should derive the same shared secret
        val sharedSecret1 = keyPair1.privateKey.sharedSecretGenerator()
            .generateSharedSecret(keyPair2.publicKey)
        val sharedSecret2 = keyPair2.privateKey.sharedSecretGenerator()
            .generateSharedSecret(keyPair1.publicKey)

        assertContentEquals(
            sharedSecret1,
            sharedSecret2,
            "Shared secrets don't match"
        )
    }

    @Test
    fun testKeyAgreementFromPublicKey() = testWithAlgorithm {
        val keyPair1 = algorithm.keyPairGenerator().generateKey()
        val keyPair2 = algorithm.keyPairGenerator().generateKey()

        // Generate shared secret from public key side
        val sharedSecret1 = keyPair1.publicKey.sharedSecretGenerator()
            .generateSharedSecret(keyPair2.privateKey)
        val sharedSecret2 = keyPair2.privateKey.sharedSecretGenerator()
            .generateSharedSecret(keyPair1.publicKey)

        assertContentEquals(
            sharedSecret1,
            sharedSecret2,
            "Shared secrets from public key don't match"
        )
    }

    @Test
    fun testDifferentKeyPairsProduceDifferentSecrets() = testWithAlgorithm {
        val keyPair1 = algorithm.keyPairGenerator().generateKey()
        val keyPair2 = algorithm.keyPairGenerator().generateKey()
        val keyPair3 = algorithm.keyPairGenerator().generateKey()

        val secret12 = keyPair1.privateKey.sharedSecretGenerator()
            .generateSharedSecret(keyPair2.publicKey)
        val secret13 = keyPair1.privateKey.sharedSecretGenerator()
            .generateSharedSecret(keyPair3.publicKey)

        assertNotEquals(
            secret12,
            secret13,
            "Different key pairs should produce different shared secrets"
        )
    }

    @Test
    fun testPublicKeyRoundTrip() = testWithAlgorithm {
        val keyPair = algorithm.keyPairGenerator().generateKey()
        val publicKeyDecoder = algorithm.publicKeyDecoder()

        // RAW format round-trip
        val rawBytes = keyPair.publicKey.encodeToByteString(X25519.PublicKey.Format.RAW)
        val decodedRaw = publicKeyDecoder.decodeFromByteString(X25519.PublicKey.Format.RAW, rawBytes)
        assertContentEquals(
            rawBytes,
            decodedRaw.encodeToByteString(X25519.PublicKey.Format.RAW),
            "Public key RAW round-trip failed"
        )

        // DER format round-trip
        val derBytes = keyPair.publicKey.encodeToByteString(X25519.PublicKey.Format.DER)
        val decodedDer = publicKeyDecoder.decodeFromByteString(X25519.PublicKey.Format.DER, derBytes)
        assertContentEquals(
            derBytes,
            decodedDer.encodeToByteString(X25519.PublicKey.Format.DER),
            "Public key DER round-trip failed"
        )

        // PEM format round-trip
        val pemBytes = keyPair.publicKey.encodeToByteString(X25519.PublicKey.Format.PEM)
        val decodedPem = publicKeyDecoder.decodeFromByteString(X25519.PublicKey.Format.PEM, pemBytes)
        assertContentEquals(
            derBytes,
            decodedPem.encodeToByteString(X25519.PublicKey.Format.DER),
            "Public key PEM round-trip failed"
        )
    }

    @Test
    fun testPrivateKeyRoundTrip() = testWithAlgorithm {
        val keyPair = algorithm.keyPairGenerator().generateKey()
        val privateKeyDecoder = algorithm.privateKeyDecoder()

        // RAW format round-trip
        val rawBytes = keyPair.privateKey.encodeToByteString(X25519.PrivateKey.Format.RAW)
        val decodedRaw = privateKeyDecoder.decodeFromByteString(X25519.PrivateKey.Format.RAW, rawBytes)
        assertContentEquals(
            rawBytes,
            decodedRaw.encodeToByteString(X25519.PrivateKey.Format.RAW),
            "Private key RAW round-trip failed"
        )

        // DER format round-trip
        val derBytes = keyPair.privateKey.encodeToByteString(X25519.PrivateKey.Format.DER)
        val decodedDer = privateKeyDecoder.decodeFromByteString(X25519.PrivateKey.Format.DER, derBytes)
        // Compare RAW to avoid DER encoding differences (publicKey presence)
        assertContentEquals(
            rawBytes,
            decodedDer.encodeToByteString(X25519.PrivateKey.Format.RAW),
            "Private key DER round-trip failed"
        )

        // PEM format round-trip
        val pemBytes = keyPair.privateKey.encodeToByteString(X25519.PrivateKey.Format.PEM)
        val decodedPem = privateKeyDecoder.decodeFromByteString(X25519.PrivateKey.Format.PEM, pemBytes)
        assertContentEquals(
            rawBytes,
            decodedPem.encodeToByteString(X25519.PrivateKey.Format.RAW),
            "Private key PEM round-trip failed"
        )
    }

    @Test
    fun testDecodedKeyCanPerformKeyAgreement() = testWithAlgorithm {
        val keyPair1 = algorithm.keyPairGenerator().generateKey()
        val keyPair2 = algorithm.keyPairGenerator().generateKey()
        val privateKeyDecoder = algorithm.privateKeyDecoder()
        val publicKeyDecoder = algorithm.publicKeyDecoder()

        // Decode keys from RAW format
        val rawPrivateKey = keyPair1.privateKey.encodeToByteString(X25519.PrivateKey.Format.RAW)
        val rawPublicKey = keyPair2.publicKey.encodeToByteString(X25519.PublicKey.Format.RAW)

        val decodedPrivateKey = privateKeyDecoder.decodeFromByteString(X25519.PrivateKey.Format.RAW, rawPrivateKey)
        val decodedPublicKey = publicKeyDecoder.decodeFromByteString(X25519.PublicKey.Format.RAW, rawPublicKey)

        // Perform key agreement with decoded keys
        val sharedSecret1 = decodedPrivateKey.sharedSecretGenerator()
            .generateSharedSecret(decodedPublicKey)

        // Should match original keys
        val sharedSecret2 = keyPair1.privateKey.sharedSecretGenerator()
            .generateSharedSecret(keyPair2.publicKey)

        assertContentEquals(
            sharedSecret1,
            sharedSecret2,
            "Decoded key agreement doesn't match original"
        )
    }

    @Test
    fun testPublicKeyFromPrivateKey() = testWithAlgorithm {
        val keyPair = algorithm.keyPairGenerator().generateKey()

        // Get public key from private key
        val derivedPublicKey = keyPair.privateKey.getPublicKey()

        // Compare with original public key
        assertContentEquals(
            keyPair.publicKey.encodeToByteString(X25519.PublicKey.Format.RAW),
            derivedPublicKey.encodeToByteString(X25519.PublicKey.Format.RAW),
            "Derived public key doesn't match original"
        )
    }

    // RFC 7748 Section 6.1 Test Vectors
    // https://datatracker.ietf.org/doc/html/rfc7748#section-6.1
    private data class X25519TestVector(
        val alicePrivate: String,  // hex, 32 bytes (clamped scalar)
        val alicePublic: String,   // hex, 32 bytes
        val bobPrivate: String,    // hex, 32 bytes (clamped scalar)
        val bobPublic: String,     // hex, 32 bytes
        val sharedSecret: String,  // hex, 32 bytes
    )

    private val rfcTestVector = X25519TestVector(
        alicePrivate = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        alicePublic = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        bobPrivate = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        bobPublic = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        sharedSecret = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    )

    @OptIn(ExperimentalStdlibApi::class)
    @Test
    fun testRfc7748KeyAgreement() = testWithAlgorithm {
        val privateKeyDecoder = algorithm.privateKeyDecoder()
        val publicKeyDecoder = algorithm.publicKeyDecoder()

        // Decode Alice's private key and Bob's public key
        val alicePrivate = privateKeyDecoder.decodeFromByteArray(
            X25519.PrivateKey.Format.RAW,
            rfcTestVector.alicePrivate.hexToByteArray()
        )
        val bobPublic = publicKeyDecoder.decodeFromByteArray(
            X25519.PublicKey.Format.RAW,
            rfcTestVector.bobPublic.hexToByteArray()
        )

        // Compute shared secret
        val sharedSecret = alicePrivate.sharedSecretGenerator().generateSharedSecret(bobPublic)

        assertContentEquals(
            ByteString(rfcTestVector.sharedSecret.hexToByteArray()),
            sharedSecret,
            "RFC 7748 shared secret (Alice->Bob) mismatch"
        )
    }

    @OptIn(ExperimentalStdlibApi::class)
    @Test
    fun testRfc7748KeyAgreementReverse() = testWithAlgorithm {
        val privateKeyDecoder = algorithm.privateKeyDecoder()
        val publicKeyDecoder = algorithm.publicKeyDecoder()

        // Decode Bob's private key and Alice's public key
        val bobPrivate = privateKeyDecoder.decodeFromByteArray(
            X25519.PrivateKey.Format.RAW,
            rfcTestVector.bobPrivate.hexToByteArray()
        )
        val alicePublic = publicKeyDecoder.decodeFromByteArray(
            X25519.PublicKey.Format.RAW,
            rfcTestVector.alicePublic.hexToByteArray()
        )

        // Compute shared secret
        val sharedSecret = bobPrivate.sharedSecretGenerator().generateSharedSecret(alicePublic)

        assertContentEquals(
            ByteString(rfcTestVector.sharedSecret.hexToByteArray()),
            sharedSecret,
            "RFC 7748 shared secret (Bob->Alice) mismatch"
        )
    }

    @OptIn(ExperimentalStdlibApi::class)
    @Test
    fun testRfc7748PublicKeyDerivation() = testWithAlgorithm {
        val privateKeyDecoder = algorithm.privateKeyDecoder()

        // Verify Alice's public key derivation
        val alicePrivate = privateKeyDecoder.decodeFromByteArray(
            X25519.PrivateKey.Format.RAW,
            rfcTestVector.alicePrivate.hexToByteArray()
        )
        val aliceDerivedPublic = try {
            alicePrivate.getPublicKey()
        } catch (e: Throwable) {
            if (!supportsX25519PublicKeyDerivation(e)) return@testWithAlgorithm
            throw e
        }
        assertContentEquals(
            rfcTestVector.alicePublic.hexToByteArray(),
            aliceDerivedPublic.encodeToByteArray(X25519.PublicKey.Format.RAW),
            "RFC 7748 Alice public key derivation mismatch"
        )

        // Verify Bob's public key derivation
        val bobPrivate = privateKeyDecoder.decodeFromByteArray(
            X25519.PrivateKey.Format.RAW,
            rfcTestVector.bobPrivate.hexToByteArray()
        )
        val bobDerivedPublic = bobPrivate.getPublicKey()
        assertContentEquals(
            rfcTestVector.bobPublic.hexToByteArray(),
            bobDerivedPublic.encodeToByteArray(X25519.PublicKey.Format.RAW),
            "RFC 7748 Bob public key derivation mismatch"
        )
    }
}