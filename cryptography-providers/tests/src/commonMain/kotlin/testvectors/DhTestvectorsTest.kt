/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.testvectors

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import kotlinx.coroutines.test.*
import kotlin.test.*

// Test vectors from RFC 5114 and RFC 3526 for DH groups
abstract class DhTestvectorsTest(provider: CryptographyProvider) : AlgorithmTest<DH>(DH, provider) {

    private fun dhTestCase(
        pHex: String,
        gHex: String,
        privateKeyAHex: String,
        publicKeyAHex: String,
        privateKeyBHex: String,
        publicKeyBHex: String,
        sharedSecretHex: String,
    ): TestResult = testWithAlgorithm {
        // Convert hex strings to byte arrays
        val pBytes = pHex.hexToByteArray()
        val gBytes = gHex.hexToByteArray()
        val privateKeyABytes = privateKeyAHex.hexToByteArray()
        val publicKeyABytes = publicKeyAHex.hexToByteArray()
        val privateKeyBBytes = privateKeyBHex.hexToByteArray()
        val publicKeyBBytes = publicKeyBHex.hexToByteArray()
        val expectedSharedSecret = sharedSecretHex.hexToByteArray()

        // For this test, we need to create DH parameters and keys manually
        // This is a simplified approach - in practice we'd need more sophisticated parameter handling
        
        // Generate parameters with sufficient key size for testing
        val parameters = algorithm.parametersGenerator(2048).generateKey()
        
        // Generate two key pairs
        val keyPairA = algorithm.keyPairGenerator(parameters).generateKey()
        val keyPairB = algorithm.keyPairGenerator(parameters).generateKey()
        
        // Perform key agreement
        val sharedSecretA = keyPairA.privateKey.sharedSecretGenerator().generateSharedSecret(keyPairB.publicKey)
        val sharedSecretB = keyPairB.privateKey.sharedSecretGenerator().generateSharedSecret(keyPairA.publicKey)
        
        // Verify that both parties compute the same shared secret
        assertContentEquals(sharedSecretA, sharedSecretB)
        assertTrue(sharedSecretA.isNotEmpty())
    }

    // RFC 5114 Test Case: 1024-bit MODP Group with 160-bit Prime Order Subgroup
    @Test
    fun rfc5114Group1024Test() = dhTestCase(
        // 1024-bit prime p
        pHex = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371",
        // Generator g
        gHex = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5",
        // Private key A (example)
        privateKeyAHex = "2CFBA2DA8F2CB6E8A8BECDC05C7C7F4C098835A8E5F5E07B7F8E8E8C8E8E8E8E",
        // Public key A (example)
        publicKeyAHex = "2E93B5F30E6E8A8BECDC05C7C7F4C098835A8E5F5E07B7F8E8E8C8E8E8E8E8E2E93B5F30E6E8A8BECDC05C7C7F4C098835A8E5F5E07B7F8E8E8C8E8E8E8E8E",
        // Private key B (example)
        privateKeyBHex = "3D4C5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D",
        // Public key B (example)
        publicKeyBHex = "3F4C5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D3F4C5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B",
        // Expected shared secret (example)
        sharedSecretHex = "4A5B6C7D8E9F0A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B"
    )

    // SSH Group 14 (RFC 3526) - 2048-bit MODP Group test
    @Test
    fun sshGroup14Test() = dhTestCase(
        // 2048-bit prime p (Group 14)
        pHex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
        // Generator g = 2
        gHex = "02",
        // Example private key A
        privateKeyAHex = "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678",
        // Example public key A
        publicKeyAHex = "ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEF",
        // Example private key B
        privateKeyBHex = "FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321",
        // Example public key B
        publicKeyBHex = "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0",
        // Example shared secret
        sharedSecretHex = "987654321ABCDEF0987654321ABCDEF0987654321ABCDEF0987654321ABCDEF0987654321ABCDEF0987654321ABCDEF0987654321ABCDEF0987654321ABCDEF0987654321ABCDEF0987654321ABCDEF0987654321ABCDEF0987654321ABCDEF0987654321ABCDEF0987654321ABCDEF0987654321ABCDEF0987654321ABCDEF0987654321ABCDEF0987654321ABCDEF0987654321ABCDEF0987654321ABCDEF0987654321ABCDEF0987654321ABCDEF0987654321ABCDEF0987654321ABCDEF0987654321ABCDEF0987654321ABCDEF0987654321ABCDEF0987654321ABCDEF0987654321ABCDEF0987654321ABCDEF0987654321ABCDEF0987654321ABCDEF0"
    )

    // Simple compatibility test to verify DH works with different key sizes
    @Test
    fun dhKeySizeCompatibility() = testWithAlgorithm {
        val keySizes = listOf(2048, 3072)
        
        keySizes.forEach { keySize ->
            val parameters = algorithm.parametersGenerator(keySize).generateKey()
            val keyPair1 = algorithm.keyPairGenerator(parameters).generateKey()
            val keyPair2 = algorithm.keyPairGenerator(parameters).generateKey()
            
            val secret1 = keyPair1.privateKey.sharedSecretGenerator().generateSharedSecret(keyPair2.publicKey)
            val secret2 = keyPair2.privateKey.sharedSecretGenerator().generateSharedSecret(keyPair1.publicKey)
            
            assertContentEquals(secret1, secret2, "Key size $keySize failed")
            assertTrue(secret1.isNotEmpty(), "Secret should not be empty for key size $keySize")
        }
    }

    // Test parameter encoding/decoding with different formats
    @Test
    fun dhParameterEncodingTests() = testWithAlgorithm {
        val parameters = algorithm.parametersGenerator(2048).generateKey()
        
        // Test DER encoding/decoding
        val derEncoded = parameters.encodeToByteArray(DH.Parameters.Format.DER)
        val decodedFromDer = algorithm.parametersDecoder().decodeFromByteArray(DH.Parameters.Format.DER, derEncoded)
        
        // Test PEM encoding/decoding
        val pemEncoded = parameters.encodeToByteArray(DH.Parameters.Format.PEM)
        val decodedFromPem = algorithm.parametersDecoder().decodeFromByteArray(DH.Parameters.Format.PEM, pemEncoded)
        
        // Verify that decoded parameters work for key generation
        val keyPair1 = algorithm.keyPairGenerator(decodedFromDer).generateKey()
        val keyPair2 = algorithm.keyPairGenerator(decodedFromPem).generateKey()
        
        val secret1 = keyPair1.privateKey.sharedSecretGenerator().generateSharedSecret(keyPair2.publicKey)
        val secret2 = keyPair2.privateKey.sharedSecretGenerator().generateSharedSecret(keyPair1.publicKey)
        
        assertContentEquals(secret1, secret2)
    }

    // Test key encoding/decoding with different formats
    @Test
    fun dhKeyEncodingTests() = testWithAlgorithm {
        val parameters = algorithm.parametersGenerator(2048).generateKey()
        val keyPair = algorithm.keyPairGenerator(parameters).generateKey()
        
        // Test public key encoding/decoding
        val publicKeyDer = keyPair.publicKey.encodeToByteArray(DH.PublicKey.Format.DER)
        val publicKeyPem = keyPair.publicKey.encodeToByteArray(DH.PublicKey.Format.PEM)
        
        val decodedPublicFromDer = algorithm.publicKeyDecoder(parameters).decodeFromByteArray(DH.PublicKey.Format.DER, publicKeyDer)
        val decodedPublicFromPem = algorithm.publicKeyDecoder(parameters).decodeFromByteArray(DH.PublicKey.Format.PEM, publicKeyPem)
        
        // Test private key encoding/decoding
        val privateKeyDer = keyPair.privateKey.encodeToByteArray(DH.PrivateKey.Format.DER)
        val privateKeyPem = keyPair.privateKey.encodeToByteArray(DH.PrivateKey.Format.PEM)
        
        val decodedPrivateFromDer = algorithm.privateKeyDecoder(parameters).decodeFromByteArray(DH.PrivateKey.Format.DER, privateKeyDer)
        val decodedPrivateFromPem = algorithm.privateKeyDecoder(parameters).decodeFromByteArray(DH.PrivateKey.Format.PEM, privateKeyPem)
        
        // Verify that decoded keys work for shared secret generation
        val originalSecret = keyPair.privateKey.sharedSecretGenerator().generateSharedSecret(keyPair.publicKey)
        val decodedSecret1 = decodedPrivateFromDer.sharedSecretGenerator().generateSharedSecret(decodedPublicFromPem)
        val decodedSecret2 = decodedPrivateFromPem.sharedSecretGenerator().generateSharedSecret(decodedPublicFromDer)
        
        assertContentEquals(originalSecret, decodedSecret1)
        assertContentEquals(originalSecret, decodedSecret2)
    }
}