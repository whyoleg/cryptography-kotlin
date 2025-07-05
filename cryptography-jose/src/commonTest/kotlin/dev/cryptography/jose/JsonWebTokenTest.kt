/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.cryptography.jose

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class JsonWebTokenTest {
    
    @Test
    fun testJwtCreation() {
        val header = JwtHeader(alg = JsonWebAlgorithms.Signature.HS256)
        val payload = JwtPayload(
            iss = "test-issuer",
            sub = "test-subject",
            aud = "test-audience",
            exp = System.currentTimeMillis() / 1000 + 3600 // 1 hour from now
        )
        
        val jwt = JsonWebToken(header = header, payload = payload)
        
        assertEquals(JsonWebAlgorithms.Signature.HS256, jwt.header.alg)
        assertEquals("JWT", jwt.header.typ)
        assertEquals("test-issuer", jwt.payload.iss)
        assertEquals("test-subject", jwt.payload.sub)
        assertEquals("test-audience", jwt.payload.aud)
        assertNotNull(jwt.payload.exp)
    }
    
    @Test
    fun testJwtHeaderDefaults() {
        val header = JwtHeader(alg = JsonWebAlgorithms.Signature.RS256)
        assertEquals("JWT", header.typ)
    }
}