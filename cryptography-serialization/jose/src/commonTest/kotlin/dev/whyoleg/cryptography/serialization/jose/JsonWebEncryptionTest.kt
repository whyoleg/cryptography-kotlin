/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class JsonWebEncryptionTest {
    
    @Test
    fun testJweHeaderSerialization() {
        val header = JweHeader(
            algorithm = JweKeyManagementAlgorithm.RSA_OAEP,
            encryptionAlgorithm = JweContentEncryptionAlgorithm.A256GCM,
            keyId = "test-key-id"
        )
        
        assertEquals(JweKeyManagementAlgorithm.RSA_OAEP, header.algorithm)
        assertEquals(JweContentEncryptionAlgorithm.A256GCM, header.encryptionAlgorithm)
        assertEquals("test-key-id", header.keyId)
    }
    
    @Test
    fun testJweCompactEncodeDecodeRoundTrip() {
        val header = JweHeader(
            algorithm = JweKeyManagementAlgorithm.A256KW,
            encryptionAlgorithm = JweContentEncryptionAlgorithm.A256GCM
        )
        val encryptedKey = "encrypted-key".toByteArray()
        val iv = "initialization-vector".toByteArray()
        val ciphertext = "ciphertext-data".toByteArray()
        val authTag = "auth-tag".toByteArray()
        
        val original = JweCompact(header, encryptedKey, iv, ciphertext, authTag)
        val encoded = original.encode()
        val decoded = JweCompact.decode(encoded)
        
        assertEquals(original, decoded)
        assertEquals(original.header.algorithm, decoded.header.algorithm)
        assertEquals(original.header.encryptionAlgorithm, decoded.header.encryptionAlgorithm)
        assertTrue(original.encryptedKey.contentEquals(decoded.encryptedKey))
        assertTrue(original.initializationVector.contentEquals(decoded.initializationVector))
        assertTrue(original.ciphertext.contentEquals(decoded.ciphertext))
        assertTrue(original.authenticationTag.contentEquals(decoded.authenticationTag))
    }
    
    @Test
    fun testJweCompactStructure() {
        val header = JweHeader(
            algorithm = JweKeyManagementAlgorithm.DIR,
            encryptionAlgorithm = JweContentEncryptionAlgorithm.A128GCM
        )
        val encryptedKey = byteArrayOf() // Empty for direct encryption
        val iv = "test-iv".toByteArray()
        val ciphertext = "test-ciphertext".toByteArray()
        val authTag = "test-tag".toByteArray()
        
        val jwe = JweCompact(header, encryptedKey, iv, ciphertext, authTag)
        val encoded = jwe.encode()
        
        // JWE should have 5 parts separated by dots
        val parts = encoded.split('.')
        assertEquals(5, parts.size)
        
        // For direct encryption, encrypted key part should be empty
        assertTrue(parts[1].isEmpty() || parts[1] == "")
    }
    
    @Test
    fun testJweAdditionalAuthenticatedData() {
        val header = JweHeader(
            algorithm = JweKeyManagementAlgorithm.RSA1_5,
            encryptionAlgorithm = JweContentEncryptionAlgorithm.A128CBC_HS256
        )
        val encryptedKey = "key".toByteArray()
        val iv = "iv".toByteArray()
        val ciphertext = "ciphertext".toByteArray()
        val authTag = "tag".toByteArray()
        
        val jwe = JweCompact(header, encryptedKey, iv, ciphertext, authTag)
        val aad = jwe.getAdditionalAuthenticatedData()
        
        assertTrue(aad.isNotEmpty())
        // AAD should be the base64url encoded header
        val aadString = aad.decodeToString()
        assertFalse(aadString.contains("."))
    }
    
    @Test
    fun testJweJsonFlattened() {
        val header = JweHeader(
            algorithm = JweKeyManagementAlgorithm.A128KW,
            encryptionAlgorithm = JweContentEncryptionAlgorithm.A128GCM
        )
        val encryptedKey = "encrypted-key".toByteArray()
        val iv = "iv".toByteArray()
        val ciphertext = "ciphertext".toByteArray()
        val authTag = "tag".toByteArray()
        
        val compact = JweCompact(header, encryptedKey, iv, ciphertext, authTag)
        val jsonFlattened = JweJson.fromCompact(compact)
        
        assertTrue(jsonFlattened.isFlattened)
        assertFalse(jsonFlattened.isGeneral)
        
        // Test conversion back to compact
        val convertedBack = jsonFlattened.toCompact()
        assertEquals(compact, convertedBack)
    }
    
    @Test
    fun testJweJsonGeneral() {
        val jweJson = JweJson(
            protectedHeader = "eyJlbmMiOiJBMTI4R0NNIn0",
            recipients = listOf(
                JweRecipient(
                    header = JweHeader(
                        algorithm = JweKeyManagementAlgorithm.RSA_OAEP,
                        encryptionAlgorithm = JweContentEncryptionAlgorithm.A128GCM
                    ),
                    encryptedKey = "key1"
                ),
                JweRecipient(
                    header = JweHeader(
                        algorithm = JweKeyManagementAlgorithm.A256KW,
                        encryptionAlgorithm = JweContentEncryptionAlgorithm.A128GCM
                    ),
                    encryptedKey = "key2"
                )
            ),
            initializationVector = "iv",
            ciphertext = "ciphertext",
            authenticationTag = "tag"
        )
        
        assertFalse(jweJson.isFlattened)
        assertTrue(jweJson.isGeneral)
        assertEquals(2, jweJson.recipients?.size)
    }
    
    @Test
    fun testJweEcdhParameters() {
        val ephemeralKey = EcPublicJsonWebKey(
            curve = JwkEllipticCurve.P256,
            xCoordinate = "test-x",
            yCoordinate = "test-y"
        )
        
        val header = JweHeader(
            algorithm = JweKeyManagementAlgorithm.ECDH_ES,
            encryptionAlgorithm = JweContentEncryptionAlgorithm.A256GCM,
            ephemeralPublicKey = ephemeralKey,
            agreementPartyUInfo = "Alice",
            agreementPartyVInfo = "Bob"
        )
        
        assertEquals(JweKeyManagementAlgorithm.ECDH_ES, header.algorithm)
        assertEquals(ephemeralKey, header.ephemeralPublicKey)
        assertEquals("Alice", header.agreementPartyUInfo)
        assertEquals("Bob", header.agreementPartyVInfo)
    }
    
    @Test
    fun testJwePbes2Parameters() {
        val header = JweHeader(
            algorithm = JweKeyManagementAlgorithm.PBES2_HS256_A128KW,
            encryptionAlgorithm = JweContentEncryptionAlgorithm.A128GCM,
            pbes2SaltInput = "salt-input",
            pbes2Count = 4096L
        )
        
        assertEquals(JweKeyManagementAlgorithm.PBES2_HS256_A128KW, header.algorithm)
        assertEquals("salt-input", header.pbes2SaltInput)
        assertEquals(4096L, header.pbes2Count)
    }
    
    @Test
    fun testJweAesGcmParameters() {
        val header = JweHeader(
            algorithm = JweKeyManagementAlgorithm.A256GCMKW,
            encryptionAlgorithm = JweContentEncryptionAlgorithm.A256GCM,
            initializationVector = "iv-value",
            authenticationTag = "tag-value"
        )
        
        assertEquals(JweKeyManagementAlgorithm.A256GCMKW, header.algorithm)
        assertEquals("iv-value", header.initializationVector)
        assertEquals("tag-value", header.authenticationTag)
    }
}