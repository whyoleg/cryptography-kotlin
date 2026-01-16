/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.default

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.providers.tests.*
import kotlin.test.*

// RFC 3526 MODP Group 14 (2048-bit) DH parameters encoded in DER format.
// This avoids the extremely slow DH parameter generation during tests.
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

abstract class DhTest(provider: CryptographyProvider) : AlgorithmTest<DH>(DH, provider) {

    // Decode predefined RFC 3526 parameters to get a proper DH.Parameters implementation
    private suspend fun AlgorithmTestScope<DH>.testParameters(): DH.Parameters {
        return algorithm.parametersDecoder().decodeFromByteArray(DH.Parameters.Format.DER, rfc3526Group14Der)
    }

    @Test
    fun testKeyGeneration() = testWithAlgorithm {
        val parameters = testParameters()
        val keyPair = parameters.keyPairGenerator().generateKey()
        assertNotNull(keyPair.publicKey)
        assertNotNull(keyPair.privateKey)
    }

    @Test
    fun testSharedSecretGeneration() = testWithAlgorithm {
        val parameters = testParameters()
        val keyPair1 = parameters.keyPairGenerator().generateKey()
        val keyPair2 = parameters.keyPairGenerator().generateKey()

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
        val parameters = testParameters()
        val keyPair = parameters.keyPairGenerator().generateKey()

        // Test public key DER encoding roundtrip
        val publicDer = keyPair.publicKey.encodeToByteArray(DH.PublicKey.Format.DER)
        val decodedPublic = algorithm.publicKeyDecoder().decodeFromByteArray(DH.PublicKey.Format.DER, publicDer)

        // Test private key DER encoding roundtrip
        val privateDer = keyPair.privateKey.encodeToByteArray(DH.PrivateKey.Format.DER)
        val decodedPrivate = algorithm.privateKeyDecoder().decodeFromByteArray(DH.PrivateKey.Format.DER, privateDer)

        // Verify decoded keys work for shared secret generation
        val originalSecret = keyPair.privateKey.sharedSecretGenerator().generateSharedSecretToByteArray(keyPair.publicKey)
        val decodedSecret = decodedPrivate.sharedSecretGenerator().generateSharedSecretToByteArray(decodedPublic)
        assertContentEquals(originalSecret, decodedSecret, "Decoded keys should produce same shared secret")
    }

    @Test
    fun testKeyEncodingPem() = testWithAlgorithm {
        val parameters = testParameters()
        val keyPair = parameters.keyPairGenerator().generateKey()

        // Test public key PEM encoding roundtrip
        val publicPem = keyPair.publicKey.encodeToByteArray(DH.PublicKey.Format.PEM)
        val decodedPublic = algorithm.publicKeyDecoder().decodeFromByteArray(DH.PublicKey.Format.PEM, publicPem)

        // Test private key PEM encoding roundtrip
        val privatePem = keyPair.privateKey.encodeToByteArray(DH.PrivateKey.Format.PEM)
        val decodedPrivate = algorithm.privateKeyDecoder().decodeFromByteArray(DH.PrivateKey.Format.PEM, privatePem)

        // Verify decoded keys work for shared secret generation
        val originalSecret = keyPair.privateKey.sharedSecretGenerator().generateSharedSecretToByteArray(keyPair.publicKey)
        val decodedSecret = decodedPrivate.sharedSecretGenerator().generateSharedSecretToByteArray(decodedPublic)
        assertContentEquals(originalSecret, decodedSecret, "Decoded keys should produce same shared secret")
    }

    @Test
    fun testParametersEncodingDer() = testWithAlgorithm {
        val parameters = testParameters()

        // Test DER encoding roundtrip
        val der = parameters.encodeToByteArray(DH.Parameters.Format.DER)
        val decoded = algorithm.parametersDecoder().decodeFromByteArray(DH.Parameters.Format.DER, der)

        // Verify decoded parameters have the same values
        assertEquals(parameters.p, decoded.p, "p should match")
        assertEquals(parameters.g, decoded.g, "g should match")

        // Verify key generation works with decoded parameters
        val keyPair = decoded.keyPairGenerator().generateKey()
        assertNotNull(keyPair.publicKey)
        assertNotNull(keyPair.privateKey)
    }

    @Test
    fun testParametersEncodingPem() = testWithAlgorithm {
        val parameters = testParameters()

        // Test PEM encoding roundtrip
        val pem = parameters.encodeToByteArray(DH.Parameters.Format.PEM)
        val decoded = algorithm.parametersDecoder().decodeFromByteArray(DH.Parameters.Format.PEM, pem)

        // Verify decoded parameters have the same values
        assertEquals(parameters.p, decoded.p, "p should match")
        assertEquals(parameters.g, decoded.g, "g should match")

        // Verify key generation works with decoded parameters
        val keyPair = decoded.keyPairGenerator().generateKey()
        assertNotNull(keyPair.publicKey)
        assertNotNull(keyPair.privateKey)
    }

    @Test
    fun testKeyPropertiesXY() = testWithAlgorithm {
        val parameters = testParameters()
        val keyPair = parameters.keyPairGenerator().generateKey()

        // Test that x and y properties are accessible
        val x = keyPair.privateKey.x
        val y = keyPair.publicKey.y

        // x and y should be non-zero (compare encoded bytes)
        val zeroBytes = byteArrayOf(0)
        assertFalse(x.encodeToByteArray().contentEquals(zeroBytes), "Private key x should not be zero")
        assertFalse(y.encodeToByteArray().contentEquals(zeroBytes), "Public key y should not be zero")

        // y should be consistent with encoded/decoded key
        val decodedPublic = algorithm.publicKeyDecoder().decodeFromByteArray(
            DH.PublicKey.Format.DER,
            keyPair.publicKey.encodeToByteArray(DH.PublicKey.Format.DER)
        )
        assertEquals(y, decodedPublic.y, "y should match after decode")

        // x should be consistent with encoded/decoded key
        val decodedPrivate = algorithm.privateKeyDecoder().decodeFromByteArray(
            DH.PrivateKey.Format.DER,
            keyPair.privateKey.encodeToByteArray(DH.PrivateKey.Format.DER)
        )
        assertEquals(x, decodedPrivate.x, "x should match after decode")
    }
}
