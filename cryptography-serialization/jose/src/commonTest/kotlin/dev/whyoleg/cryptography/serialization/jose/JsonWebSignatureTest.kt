/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class JsonWebSignatureTest {
    
    @Test
    fun testJwsHeaderSerialization() {
        val header = JwsHeader(
            algorithm = JwsAlgorithm.RS256,
            type = "JWT",
            keyId = "test-key-id"
        )
        
        assertEquals(JwsAlgorithm.RS256, header.algorithm)
        assertEquals("JWT", header.type)
        assertEquals("test-key-id", header.keyId)
    }
    
    @Test
    fun testJwsCompactEncodeDecodeRoundTrip() {
        val header = JwsHeader(
            algorithm = JwsAlgorithm.HS256,
            type = "JWT"
        )
        val payload = "Test payload".toByteArray()
        val signature = "Test signature".toByteArray()
        
        val original = JwsCompact(header, payload, signature)
        val encoded = original.encode()
        val decoded = JwsCompact.decode(encoded)
        
        assertEquals(original, decoded)
        assertEquals(original.header.algorithm, decoded.header.algorithm)
        assertEquals(original.header.type, decoded.header.type)
        assertTrue(original.payload.contentEquals(decoded.payload))
        assertTrue(original.signature.contentEquals(decoded.signature))
    }
    
    @Test
    fun testJwsCompactSigningInput() {
        val header = JwsHeader(algorithm = JwsAlgorithm.HS256)
        val payload = "Test payload".toByteArray()
        val signature = "Test signature".toByteArray()
        
        val jws = JwsCompact(header, payload, signature)
        val signingInput = jws.getSigningInput()
        
        assertTrue(signingInput.isNotEmpty())
        // Should contain header.payload without signature
        val stringInput = signingInput.decodeToString()
        assertTrue(stringInput.contains("."))
        assertFalse(stringInput.contains("..")) // Should not have double dots
    }
    
    @Test
    fun testJwsJsonFlattened() {
        val header = JwsHeader(algorithm = JwsAlgorithm.RS256)
        val payload = "Test payload".toByteArray()
        val signature = "Test signature".toByteArray()
        
        val compact = JwsCompact(header, payload, signature)
        val jsonFlattened = JwsJson.fromCompact(compact)
        
        assertTrue(jsonFlattened.isFlattened)
        assertFalse(jsonFlattened.isGeneral)
        
        // Test conversion back to compact
        val convertedBack = jsonFlattened.toCompact()
        assertEquals(compact, convertedBack)
    }
    
    @Test
    fun testJwsJsonGeneral() {
        val jwsJson = JwsJson(
            payload = "dGVzdA",
            signatures = listOf(
                JwsSignature(
                    protectedHeader = "eyJhbGciOiJSUzI1NiJ9",
                    signature = "signature1"
                ),
                JwsSignature(
                    protectedHeader = "eyJhbGciOiJFUzI1NiJ9",
                    signature = "signature2"
                )
            )
        )
        
        assertFalse(jwsJson.isFlattened)
        assertTrue(jwsJson.isGeneral)
        assertEquals(2, jwsJson.signatures?.size)
    }
    
    @Test
    fun testJwsUnsigned() {
        val header = JwsHeader(algorithm = JwsAlgorithm.NONE)
        val payload = "Test payload".toByteArray()
        val signature = byteArrayOf() // Empty signature for unsigned JWS
        
        val jws = JwsCompact(header, payload, signature)
        val encoded = jws.encode()
        
        // Should end with a dot and empty signature part
        assertTrue(encoded.endsWith("."))
        
        val decoded = JwsCompact.decode(encoded)
        assertEquals(JwsAlgorithm.NONE, decoded.header.algorithm)
        assertTrue(decoded.signature.isEmpty())
    }
}