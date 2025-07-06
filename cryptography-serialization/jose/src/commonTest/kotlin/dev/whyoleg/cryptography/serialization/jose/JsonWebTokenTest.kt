/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class JsonWebTokenTest {
    
    @Test
    fun testJwtCreation() {
        val header = JwtHeader(algorithm = JwsAlgorithm.HS256)
        val payload = JwtPayload(
            issuer = "test-issuer",
            subject = "test-subject",
            audience = listOf("test-audience"),
            expirationTime = System.currentTimeMillis() / 1000 + 3600 // 1 hour from now
        )
        
        val jwt = JsonWebToken(header = header, payload = payload)
        
        assertEquals(JwsAlgorithm.HS256, jwt.header.algorithm)
        assertEquals("JWT", jwt.header.type)
        assertEquals("test-issuer", jwt.payload.issuer)
        assertEquals("test-subject", jwt.payload.subject)
        assertEquals(listOf("test-audience"), jwt.payload.audience)
        assertEquals("test-audience", jwt.payload.singleAudience)
        assertNotNull(jwt.payload.expirationTime)
    }
    
    @Test
    fun testJwtHeaderDefaults() {
        val header = JwtHeader(algorithm = JwsAlgorithm.RS256)
        assertEquals("JWT", header.type)
    }
    
    @Test
    fun testJwtEncodeDecodeRoundTrip() {
        val header = JwtHeader(algorithm = JwsAlgorithm.HS256, keyId = "test-key")
        val payload = JwtPayload(
            issuer = "test-issuer",
            subject = "test-subject",
            audience = listOf("test-audience"),
            issuedAt = 1234567890,
            expirationTime = 1234567890 + 3600,
            jwtId = "test-jwt-id"
        )
        
        val originalJwt = JsonWebToken(header = header, payload = payload)
        val encoded = originalJwt.encode()
        val decoded = JsonWebToken.decode(encoded)
        
        assertEquals(originalJwt.header.algorithm, decoded.header.algorithm)
        assertEquals(originalJwt.header.type, decoded.header.type)
        assertEquals(originalJwt.header.keyId, decoded.header.keyId)
        assertEquals(originalJwt.payload.issuer, decoded.payload.issuer)
        assertEquals(originalJwt.payload.subject, decoded.payload.subject)
        assertEquals(originalJwt.payload.audience, decoded.payload.audience)
        assertEquals(originalJwt.payload.issuedAt, decoded.payload.issuedAt)
        assertEquals(originalJwt.payload.expirationTime, decoded.payload.expirationTime)
        assertEquals(originalJwt.payload.jwtId, decoded.payload.jwtId)
    }
    
    @Test
    fun testJwtPayloadValidation() {
        val currentTime = System.currentTimeMillis() / 1000
        
        // Test expired JWT
        val expiredPayload = JwtPayload(
            expirationTime = currentTime - 3600 // 1 hour ago
        )
        assertTrue(expiredPayload.isExpired(currentTime))
        assertFalse(expiredPayload.isValid(currentTime))
        
        // Test not yet valid JWT
        val futurePayload = JwtPayload(
            notBefore = currentTime + 3600 // 1 hour from now
        )
        assertTrue(futurePayload.isNotYetValid(currentTime))
        assertFalse(futurePayload.isValid(currentTime))
        
        // Test valid JWT
        val validPayload = JwtPayload(
            issuedAt = currentTime,
            notBefore = currentTime - 60, // 1 minute ago
            expirationTime = currentTime + 3600 // 1 hour from now
        )
        assertFalse(validPayload.isExpired(currentTime))
        assertFalse(validPayload.isNotYetValid(currentTime))
        assertTrue(validPayload.isValid(currentTime))
    }
    
    @Test
    fun testJwtPayloadMultipleAudiences() {
        val payload = JwtPayload(
            audience = listOf("audience1", "audience2", "audience3")
        )
        
        assertEquals(3, payload.audience?.size)
        assertEquals(null, payload.singleAudience) // Should be null for multiple audiences
        
        val singleAudiencePayload = JwtPayload(
            audience = listOf("single-audience")
        )
        assertEquals("single-audience", singleAudiencePayload.singleAudience)
    }
}