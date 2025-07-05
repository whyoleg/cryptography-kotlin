/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.cryptography.jose

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class JsonWebKeyTest {
    
    @Test
    fun testJwkCreation() {
        val jwk = JsonWebKey(
            kty = JsonWebKey.KEY_TYPE_RSA,
            use = JsonWebKey.USE_SIGNATURE,
            alg = JsonWebAlgorithms.Signature.RS256,
            kid = "test-key-id"
        )
        
        assertEquals(JsonWebKey.KEY_TYPE_RSA, jwk.kty)
        assertEquals(JsonWebKey.USE_SIGNATURE, jwk.use)
        assertEquals(JsonWebAlgorithms.Signature.RS256, jwk.alg)
        assertEquals("test-key-id", jwk.kid)
    }
    
    @Test
    fun testJwkSetOperations() {
        val key1 = JsonWebKey(
            kty = JsonWebKey.KEY_TYPE_RSA,
            use = JsonWebKey.USE_SIGNATURE,
            alg = JsonWebAlgorithms.Signature.RS256,
            kid = "key-1"
        )
        
        val key2 = JsonWebKey(
            kty = JsonWebKey.KEY_TYPE_EC,
            use = JsonWebKey.USE_ENCRYPTION,
            alg = JsonWebAlgorithms.Signature.ES256,
            kid = "key-2"
        )
        
        val jwkSet = JsonWebKeySet(keys = listOf(key1, key2))
        
        // Test finding by key ID
        val foundKey1 = jwkSet.findByKeyId("key-1")
        assertNotNull(foundKey1)
        assertEquals("key-1", foundKey1.kid)
        
        val notFoundKey = jwkSet.findByKeyId("non-existent")
        assertNull(notFoundKey)
        
        // Test finding by use
        val signatureKeys = jwkSet.findByUse(JsonWebKey.USE_SIGNATURE)
        assertEquals(1, signatureKeys.size)
        assertEquals("key-1", signatureKeys.first().kid)
        
        // Test finding by algorithm
        val rs256Keys = jwkSet.findByAlgorithm(JsonWebAlgorithms.Signature.RS256)
        assertEquals(1, rs256Keys.size)
        assertEquals("key-1", rs256Keys.first().kid)
    }
}