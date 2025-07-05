/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

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
    fun testJwkSetOperations() {
        val key1 = JsonWebKey(
            keyType = JwkKeyType.RSA,
            keyUse = JwkKeyUse.SIGNATURE,
            algorithm = JwsAlgorithm.RS256,
            keyId = "key-1"
        )
        
        val key2 = JsonWebKey(
            keyType = JwkKeyType.EC,
            keyUse = JwkKeyUse.ENCRYPTION,
            algorithm = JwsAlgorithm.ES256,
            keyId = "key-2"
        )
        
        val jwkSet = JsonWebKeySet(keys = listOf(key1, key2))
        
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
    }
}