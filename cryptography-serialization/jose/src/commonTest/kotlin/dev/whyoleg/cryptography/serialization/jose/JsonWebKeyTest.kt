/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.assertFalse

class JsonWebKeyTest {
    
    @Test
    fun testJwkCreation() {
        val jwk = JsonWebKey(
            keyType = JwkKeyType.RSA,
            keyUse = JwkKeyUse.SIGNATURE,
            algorithm = JwsAlgorithm.RS256,
            keyId = "test-key-id"
        )
        
        assertEquals(JwkKeyType.RSA, jwk.keyType)
        assertEquals(JwkKeyUse.SIGNATURE, jwk.keyUse)
        assertEquals(JwsAlgorithm.RS256, jwk.algorithm)
        assertEquals("test-key-id", jwk.keyId)
    }
    
    @Test
    fun testRsaPublicKey() {
        val jwk = JsonWebKey(
            keyType = JwkKeyType.RSA,
            keyUse = JwkKeyUse.SIGNATURE,
            algorithm = JwsAlgorithm.RS256,
            keyId = "rsa-public",
            modulus = "test-modulus",
            exponent = "AQAB"
        )
        
        assertTrue(jwk.isPublicKey)
        assertFalse(jwk.isPrivateKey)
        assertEquals("test-modulus", jwk.modulus)
        assertEquals("AQAB", jwk.exponent)
    }
    
    @Test
    fun testRsaPrivateKey() {
        val jwk = JsonWebKey(
            keyType = JwkKeyType.RSA,
            keyUse = JwkKeyUse.SIGNATURE,
            algorithm = JwsAlgorithm.RS256,
            keyId = "rsa-private",
            modulus = "test-modulus",
            exponent = "AQAB",
            privateKey = "test-private-exponent"
        )
        
        assertFalse(jwk.isPublicKey)
        assertTrue(jwk.isPrivateKey)
        assertEquals("test-private-exponent", jwk.privateKey)
    }
    
    @Test
    fun testEcPublicKey() {
        val jwk = JsonWebKey(
            keyType = JwkKeyType.EC,
            keyUse = JwkKeyUse.SIGNATURE,
            algorithm = JwsAlgorithm.ES256,
            keyId = "ec-public",
            curve = JwkEllipticCurve.P256,
            xCoordinate = "test-x",
            yCoordinate = "test-y"
        )
        
        assertTrue(jwk.isPublicKey)
        assertFalse(jwk.isPrivateKey)
        assertEquals(JwkEllipticCurve.P256, jwk.curve)
        assertEquals("test-x", jwk.xCoordinate)
        assertEquals("test-y", jwk.yCoordinate)
    }
    
    @Test
    fun testSymmetricKey() {
        val jwk = JsonWebKey(
            keyType = JwkKeyType.SYMMETRIC,
            keyUse = JwkKeyUse.SIGNATURE,
            algorithm = JwsAlgorithm.HS256,
            keyId = "symmetric",
            keyValue = "test-key-value"
        )
        
        assertFalse(jwk.isPublicKey)
        assertTrue(jwk.isPrivateKey)
        assertEquals("test-key-value", jwk.keyValue)
    }
    
    @Test
    fun testJwkSetOperations() {
        val rsaKey = JsonWebKey(
            keyType = JwkKeyType.RSA,
            keyUse = JwkKeyUse.SIGNATURE,
            algorithm = JwsAlgorithm.RS256,
            keyId = "key-1",
            modulus = "test-modulus",
            exponent = "AQAB"
        )
        
        val ecKey = JsonWebKey(
            keyType = JwkKeyType.EC,
            keyUse = JwkKeyUse.ENCRYPTION,
            algorithm = JwsAlgorithm.ES256,
            keyId = "key-2",
            curve = JwkEllipticCurve.P256,
            xCoordinate = "test-x",
            yCoordinate = "test-y"
        )
        
        val jwkSet = JsonWebKeySet(keys = listOf(rsaKey, ecKey))
        
        // Test finding by key ID
        val foundKey1 = jwkSet.findByKeyId("key-1")
        assertNotNull(foundKey1)
        assertEquals("key-1", foundKey1.keyId)
        
        val notFoundKey = jwkSet.findByKeyId("non-existent")
        assertNull(notFoundKey)
        
        // Test finding by use
        val signatureKeys = jwkSet.findByUse(JwkKeyUse.SIGNATURE)
        assertEquals(1, signatureKeys.size)
        assertEquals("key-1", signatureKeys.first().keyId)
        
        // Test finding by algorithm
        val rs256Keys = jwkSet.findByAlgorithm(JwsAlgorithm.RS256)
        assertEquals(1, rs256Keys.size)
        assertEquals("key-1", rs256Keys.first().keyId)
        
        // Test finding by key type
        val rsaKeys = jwkSet.findByKeyType(JwkKeyType.RSA)
        assertEquals(1, rsaKeys.size)
        assertEquals("key-1", rsaKeys.first().keyId)
        
        // Test finding public keys
        val publicKeys = jwkSet.findPublicKeys()
        assertEquals(2, publicKeys.size)
    }
}