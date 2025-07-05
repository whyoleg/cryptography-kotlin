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
            audience = "test-audience",
            expirationTime = System.currentTimeMillis() / 1000 + 3600 // 1 hour from now
        )
        
        val jwt = JsonWebToken(header = header, payload = payload)
        
        assertEquals(JwsAlgorithm.HS256, jwt.header.algorithm)
        assertEquals("JWT", jwt.header.type)
        assertEquals("test-issuer", jwt.payload.issuer)
        assertEquals("test-subject", jwt.payload.subject)
        assertEquals("test-audience", jwt.payload.audience)
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
            audience = "test-audience",
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
}