/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests.default

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.tests.*
import kotlin.test.*

abstract class DhTest(provider: CryptographyProvider) : AlgorithmTest<DH>(DH, provider) {
    
    @Test
    fun testBasicDhKeyAgreement() = testWithAlgorithm {
        // Generate DH parameters
        val parameters = algorithm.parametersGenerator(2048).generateKey()
        
        // Generate two key pairs
        val keyPair1 = algorithm.keyPairGenerator(parameters).generateKey()
        val keyPair2 = algorithm.keyPairGenerator(parameters).generateKey()
        
        // Generate shared secrets
        val secret1 = keyPair1.privateKey.sharedSecretGenerator().generateSharedSecret(keyPair2.publicKey)
        val secret2 = keyPair2.privateKey.sharedSecretGenerator().generateSharedSecret(keyPair1.publicKey)
        
        // Secrets should be the same
        assertContentEquals(secret1, secret2)
        assertTrue(secret1.isNotEmpty())
    }
    
    @Test
    fun testDhParametersEncodingDecoding() = testWithAlgorithm {
        // Generate and encode DH parameters
        val originalParameters = algorithm.parametersGenerator(2048).generateKey()
        
        if (supportsKeyFormat(DH.Parameters.Format.DER)) {
            val derEncoded = originalParameters.encodeToByteArray(DH.Parameters.Format.DER)
            val decodedFromDer = algorithm.parametersDecoder().decodeFromByteArray(DH.Parameters.Format.DER, derEncoded)
            
            // Test that keys generated with decoded parameters work
            val keyPair1 = algorithm.keyPairGenerator(decodedFromDer).generateKey()
            val keyPair2 = algorithm.keyPairGenerator(originalParameters).generateKey()
            
            val secret1 = keyPair1.privateKey.sharedSecretGenerator().generateSharedSecret(keyPair2.publicKey)
            val secret2 = keyPair2.privateKey.sharedSecretGenerator().generateSharedSecret(keyPair1.publicKey)
            
            assertContentEquals(secret1, secret2)
        }
        
        if (supportsKeyFormat(DH.Parameters.Format.PEM)) {
            val pemEncoded = originalParameters.encodeToByteArray(DH.Parameters.Format.PEM)
            
            // Verify PEM format
            val pemString = pemEncoded.decodeToString()
            assertTrue(pemString.contains("-----BEGIN DH PARAMETERS-----"))
            assertTrue(pemString.contains("-----END DH PARAMETERS-----"))
            
            val decodedFromPem = algorithm.parametersDecoder().decodeFromByteArray(DH.Parameters.Format.PEM, pemEncoded)
            
            // Test that keys generated with decoded parameters work
            val keyPair1 = algorithm.keyPairGenerator(decodedFromPem).generateKey()
            val keyPair2 = algorithm.keyPairGenerator(originalParameters).generateKey()
            
            val secret1 = keyPair1.privateKey.sharedSecretGenerator().generateSharedSecret(keyPair2.publicKey)
            val secret2 = keyPair2.privateKey.sharedSecretGenerator().generateSharedSecret(keyPair1.publicKey)
            
            assertContentEquals(secret1, secret2)
        }
    }
    
    @Test
    fun testDhKeyEncodingDecoding() = testWithAlgorithm {
        val parameters = algorithm.parametersGenerator(2048).generateKey()
        val keyPair = algorithm.keyPairGenerator(parameters).generateKey()
        
        // Test public key encoding/decoding
        if (supportsKeyFormat(DH.PublicKey.Format.DER)) {
            val publicKeyDer = keyPair.publicKey.encodeToByteArray(DH.PublicKey.Format.DER)
            val decodedPublicFromDer = algorithm.publicKeyDecoder(parameters).decodeFromByteArray(DH.PublicKey.Format.DER, publicKeyDer)
            
            // Verify key works
            val originalSecret = keyPair.privateKey.sharedSecretGenerator().generateSharedSecret(keyPair.publicKey)
            val decodedSecret = keyPair.privateKey.sharedSecretGenerator().generateSharedSecret(decodedPublicFromDer)
            assertContentEquals(originalSecret, decodedSecret)
        }
        
        if (supportsKeyFormat(DH.PublicKey.Format.PEM)) {
            val publicKeyPem = keyPair.publicKey.encodeToByteArray(DH.PublicKey.Format.PEM)
            
            // Verify PEM format
            val publicPemString = publicKeyPem.decodeToString()
            assertTrue(publicPemString.contains("-----BEGIN PUBLIC KEY-----"))
            assertTrue(publicPemString.contains("-----END PUBLIC KEY-----"))
            
            val decodedPublicFromPem = algorithm.publicKeyDecoder(parameters).decodeFromByteArray(DH.PublicKey.Format.PEM, publicKeyPem)
            
            // Verify key works
            val originalSecret = keyPair.privateKey.sharedSecretGenerator().generateSharedSecret(keyPair.publicKey)
            val decodedSecret = keyPair.privateKey.sharedSecretGenerator().generateSharedSecret(decodedPublicFromPem)
            assertContentEquals(originalSecret, decodedSecret)
        }
        
        // Test private key encoding/decoding
        if (supportsKeyFormat(DH.PrivateKey.Format.DER)) {
            val privateKeyDer = keyPair.privateKey.encodeToByteArray(DH.PrivateKey.Format.DER)
            val decodedPrivateFromDer = algorithm.privateKeyDecoder(parameters).decodeFromByteArray(DH.PrivateKey.Format.DER, privateKeyDer)
            
            // Verify key works
            val originalSecret = keyPair.privateKey.sharedSecretGenerator().generateSharedSecret(keyPair.publicKey)
            val decodedSecret = decodedPrivateFromDer.sharedSecretGenerator().generateSharedSecret(keyPair.publicKey)
            assertContentEquals(originalSecret, decodedSecret)
        }
        
        if (supportsKeyFormat(DH.PrivateKey.Format.PEM)) {
            val privateKeyPem = keyPair.privateKey.encodeToByteArray(DH.PrivateKey.Format.PEM)
            
            // Verify PEM format
            val privatePemString = privateKeyPem.decodeToString()
            assertTrue(privatePemString.contains("-----BEGIN PRIVATE KEY-----"))
            assertTrue(privatePemString.contains("-----END PRIVATE KEY-----"))
            
            val decodedPrivateFromPem = algorithm.privateKeyDecoder(parameters).decodeFromByteArray(DH.PrivateKey.Format.PEM, privateKeyPem)
            
            // Verify key works
            val originalSecret = keyPair.privateKey.sharedSecretGenerator().generateSharedSecret(keyPair.publicKey)
            val decodedSecret = decodedPrivateFromPem.sharedSecretGenerator().generateSharedSecret(keyPair.publicKey)
            assertContentEquals(originalSecret, decodedSecret)
        }
    }
    
    @Test
    fun testMultipleKeySizes() = testWithAlgorithm {
        val keySizes = listOf(2048, 3072)
        
        keySizes.forEach { keySize ->
            val parameters = algorithm.parametersGenerator(keySize).generateKey()
            val keyPair1 = algorithm.keyPairGenerator(parameters).generateKey()
            val keyPair2 = algorithm.keyPairGenerator(parameters).generateKey()
            
            val secret1 = keyPair1.privateKey.sharedSecretGenerator().generateSharedSecret(keyPair2.publicKey)
            val secret2 = keyPair2.privateKey.sharedSecretGenerator().generateSharedSecret(keyPair1.publicKey)
            
            assertContentEquals(secret1, secret2, "Key size $keySize failed")
            assertTrue(secret1.isNotEmpty(), "Secret should not be empty for key size $keySize")
            
            // Verify secret length is reasonable for the key size
            assertTrue(secret1.size >= keySize / 16, "Secret too short for key size $keySize") // Rough estimate
        }
    }
    
    @Test
    fun testParameterMismatchDetection() = testWithAlgorithm {
        // Generate two different parameter sets
        val parameters1 = algorithm.parametersGenerator(2048).generateKey()
        val parameters2 = algorithm.parametersGenerator(2048).generateKey()
        
        // Generate key pairs with different parameters
        val keyPair1 = algorithm.keyPairGenerator(parameters1).generateKey()
        
        // Test that parameters are actually different (this might succeed in rare cases)
        val params1Der = parameters1.encodeToByteArray(DH.Parameters.Format.DER)
        val params2Der = parameters2.encodeToByteArray(DH.Parameters.Format.DER)
        
        if (!params1Der.contentEquals(params2Der)) {
            // Only test mismatch detection if parameters are actually different
            if (supportsKeyFormat(DH.PublicKey.Format.DER)) {
                val publicKeyDer = keyPair1.publicKey.encodeToByteArray(DH.PublicKey.Format.DER)
                
                // This should fail because we're using parameters2 to decode keys generated with parameters1
                assertFailsWith<Exception> {
                    algorithm.publicKeyDecoder(parameters2).decodeFromByteArray(DH.PublicKey.Format.DER, publicKeyDer)
                }
            }
            
            if (supportsKeyFormat(DH.PrivateKey.Format.DER)) {
                val privateKeyDer = keyPair1.privateKey.encodeToByteArray(DH.PrivateKey.Format.DER)
                
                assertFailsWith<Exception> {
                    algorithm.privateKeyDecoder(parameters2).decodeFromByteArray(DH.PrivateKey.Format.DER, privateKeyDer)
                }
            }
        }
    }
    
    @Test
    fun testCrossCompatibility() = testWithAlgorithm {
        // Test that keys encoded/decoded still work for key agreement
        val parameters = algorithm.parametersGenerator(2048).generateKey()
        val keyPair1 = algorithm.keyPairGenerator(parameters).generateKey()
        val keyPair2 = algorithm.keyPairGenerator(parameters).generateKey()
        
        val originalSecret = keyPair1.privateKey.sharedSecretGenerator().generateSharedSecret(keyPair2.publicKey)
        
        // Test DER encoding if supported
        if (supportsKeyFormat(DH.PublicKey.Format.DER) && supportsKeyFormat(DH.PrivateKey.Format.DER)) {
            val publicKey1Der = keyPair1.publicKey.encodeToByteArray(DH.PublicKey.Format.DER)
            val privateKey1Der = keyPair1.privateKey.encodeToByteArray(DH.PrivateKey.Format.DER)
            
            val decodedPublicKey1 = algorithm.publicKeyDecoder(parameters).decodeFromByteArray(DH.PublicKey.Format.DER, publicKey1Der)
            val decodedPrivateKey1 = algorithm.privateKeyDecoder(parameters).decodeFromByteArray(DH.PrivateKey.Format.DER, privateKey1Der)
            
            val secret1 = decodedPrivateKey1.sharedSecretGenerator().generateSharedSecret(keyPair2.publicKey)
            val secret2 = keyPair1.privateKey.sharedSecretGenerator().generateSharedSecret(decodedPublicKey1)
            val secret3 = decodedPrivateKey1.sharedSecretGenerator().generateSharedSecret(decodedPublicKey1)
            
            assertContentEquals(originalSecret, secret1)
            assertContentEquals(originalSecret, secret2)
            assertContentEquals(originalSecret, secret3)
        }
        
        // Test PEM encoding if supported
        if (supportsKeyFormat(DH.PublicKey.Format.PEM) && supportsKeyFormat(DH.PrivateKey.Format.PEM)) {
            val publicKey2Pem = keyPair2.publicKey.encodeToByteArray(DH.PublicKey.Format.PEM)
            val privateKey2Pem = keyPair2.privateKey.encodeToByteArray(DH.PrivateKey.Format.PEM)
            
            val decodedPublicKey2 = algorithm.publicKeyDecoder(parameters).decodeFromByteArray(DH.PublicKey.Format.PEM, publicKey2Pem)
            val decodedPrivateKey2 = algorithm.privateKeyDecoder(parameters).decodeFromByteArray(DH.PrivateKey.Format.PEM, privateKey2Pem)
            
            val secret1 = keyPair1.privateKey.sharedSecretGenerator().generateSharedSecret(decodedPublicKey2)
            val secret2 = decodedPrivateKey2.sharedSecretGenerator().generateSharedSecret(keyPair1.publicKey)
            
            assertContentEquals(originalSecret, secret1)
            assertContentEquals(originalSecret, secret2)
        }
    }
}