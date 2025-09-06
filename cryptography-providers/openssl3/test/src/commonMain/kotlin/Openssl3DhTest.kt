/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.openssl3.test

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import dev.whyoleg.cryptography.providers.openssl3.*
import kotlinx.coroutines.test.*
import kotlin.test.*

class Openssl3DhTest : LibCrypto3Test() {
    private val provider = CryptographyProvider.Openssl3
    
    @Test
    fun testBasicDhKeyAgreement() = runTest {
        val dh = provider.getOrNull(DH) ?: run {
            println("DH not supported by OpenSSL provider")
            return@runTest
        }
        
        // Generate DH parameters
        val parameters = dh.parametersGenerator(2048).generateKey()
        
        // Generate two key pairs
        val keyPair1 = dh.keyPairGenerator(parameters).generateKey()
        val keyPair2 = dh.keyPairGenerator(parameters).generateKey()
        
        // Generate shared secrets
        val secret1 = keyPair1.privateKey.sharedSecretGenerator().generateSharedSecret(keyPair2.publicKey)
        val secret2 = keyPair2.privateKey.sharedSecretGenerator().generateSharedSecret(keyPair1.publicKey)
        
        // Secrets should be the same
        assertContentEquals(secret1, secret2)
        assertTrue(secret1.isNotEmpty())
    }
    
    @Test
    fun testDhParametersEncodingDecoding() = runTest {
        val dh = provider.getOrNull(DH) ?: run {
            println("DH not supported by OpenSSL provider")
            return@runTest
        }
        
        // Generate and encode DH parameters
        val originalParameters = dh.parametersGenerator(2048).generateKey()
        val derEncoded = originalParameters.encodeToByteArray(DH.Parameters.Format.DER)
        val pemEncoded = originalParameters.encodeToByteArray(DH.Parameters.Format.PEM)
        
        // Verify PEM format
        val pemString = pemEncoded.decodeToString()
        assertTrue(pemString.contains("-----BEGIN DH PARAMETERS-----"))
        assertTrue(pemString.contains("-----END DH PARAMETERS-----"))
        
        // Decode parameters
        val decodedFromDer = dh.parametersDecoder().decodeFromByteArray(DH.Parameters.Format.DER, derEncoded)
        val decodedFromPem = dh.parametersDecoder().decodeFromByteArray(DH.Parameters.Format.PEM, pemEncoded)
        
        // Test that keys generated with decoded parameters work
        val keyPair1 = dh.keyPairGenerator(decodedFromDer).generateKey()
        val keyPair2 = dh.keyPairGenerator(decodedFromPem).generateKey()
        
        val secret1 = keyPair1.privateKey.sharedSecretGenerator().generateSharedSecret(keyPair2.publicKey)
        val secret2 = keyPair2.privateKey.sharedSecretGenerator().generateSharedSecret(keyPair1.publicKey)
        
        assertContentEquals(secret1, secret2)
    }
    
    @Test
    fun testDhKeyEncodingDecoding() = runTest {
        val dh = provider.getOrNull(DH) ?: run {
            println("DH not supported by OpenSSL provider")
            return@runTest
        }
        
        val parameters = dh.parametersGenerator(2048).generateKey()
        val keyPair = dh.keyPairGenerator(parameters).generateKey()
        
        // Test public key encoding/decoding
        val publicKeyDer = keyPair.publicKey.encodeToByteArray(DH.PublicKey.Format.DER)
        val publicKeyPem = keyPair.publicKey.encodeToByteArray(DH.PublicKey.Format.PEM)
        
        val decodedPublicFromDer = dh.publicKeyDecoder(parameters).decodeFromByteArray(DH.PublicKey.Format.DER, publicKeyDer)
        val decodedPublicFromPem = dh.publicKeyDecoder(parameters).decodeFromByteArray(DH.PublicKey.Format.PEM, publicKeyPem)
        
        // Test private key encoding/decoding
        val privateKeyDer = keyPair.privateKey.encodeToByteArray(DH.PrivateKey.Format.DER)
        val privateKeyPem = keyPair.privateKey.encodeToByteArray(DH.PrivateKey.Format.PEM)
        
        val decodedPrivateFromDer = dh.privateKeyDecoder(parameters).decodeFromByteArray(DH.PrivateKey.Format.DER, privateKeyDer)
        val decodedPrivateFromPem = dh.privateKeyDecoder(parameters).decodeFromByteArray(DH.PrivateKey.Format.PEM, privateKeyPem)
        
        // Test that decoded keys can generate the same shared secret
        val originalSecret = keyPair.privateKey.sharedSecretGenerator().generateSharedSecret(keyPair.publicKey)
        val decodedSecret1 = decodedPrivateFromDer.sharedSecretGenerator().generateSharedSecret(decodedPublicFromPem)
        val decodedSecret2 = decodedPrivateFromPem.sharedSecretGenerator().generateSharedSecret(decodedPublicFromDer)
        
        assertContentEquals(originalSecret, decodedSecret1)
        assertContentEquals(originalSecret, decodedSecret2)
    }
    
    @Test
    fun testMultipleKeySizes() = runTest {
        val dh = provider.getOrNull(DH) ?: run {
            println("DH not supported by OpenSSL provider")
            return@runTest
        }
        
        val keySizes = listOf(2048, 3072)
        
        keySizes.forEach { keySize ->
            val parameters = dh.parametersGenerator(keySize).generateKey()
            val keyPair1 = dh.keyPairGenerator(parameters).generateKey()
            val keyPair2 = dh.keyPairGenerator(parameters).generateKey()
            
            val secret1 = keyPair1.privateKey.sharedSecretGenerator().generateSharedSecret(keyPair2.publicKey)
            val secret2 = keyPair2.privateKey.sharedSecretGenerator().generateSharedSecret(keyPair1.publicKey)
            
            assertContentEquals(secret1, secret2, "Key size $keySize failed")
            assertTrue(secret1.isNotEmpty(), "Secret should not be empty for key size $keySize")
        }
    }
}