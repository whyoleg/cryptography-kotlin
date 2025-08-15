/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.jose

import kotlin.test.*

class JsonWebKeyTest {

    @Test
    fun testRsaPublicKey() {
        val jwk = RsaPublicJsonWebKey(
            modulus = "test-modulus",
            exponent = "AQAB",
            keyUse = JwkKeyUse.SIGNATURE,
            algorithm = JwsAlgorithm.RS256,
            keyId = "rsa-public"
        )

        assertEquals(JwkKeyType.RSA, jwk.keyType)
        assertEquals(JwkKeyUse.SIGNATURE, jwk.keyUse)
        assertEquals(JwsAlgorithm.RS256, jwk.algorithm)
        assertEquals("rsa-public", jwk.keyId)
        assertTrue(jwk.isPublicKey)
        assertFalse(jwk.isPrivateKey)
        assertEquals("test-modulus", jwk.modulus)
        assertEquals("AQAB", jwk.exponent)
    }

    @Test
    fun testRsaPrivateKey() {
        val jwk = RsaPrivateJsonWebKey(
            modulus = "test-modulus",
            exponent = "AQAB",
            privateExponent = "test-private-exponent",
            keyUse = JwkKeyUse.SIGNATURE,
            algorithm = JwsAlgorithm.RS256,
            keyId = "rsa-private"
        )

        assertEquals(JwkKeyType.RSA, jwk.keyType)
        assertFalse(jwk.isPublicKey)
        assertTrue(jwk.isPrivateKey)
        assertEquals("test-private-exponent", jwk.privateExponent)
        assertEquals("test-modulus", jwk.modulus)
        assertEquals("AQAB", jwk.exponent)
    }

    @Test
    fun testEcPublicKey() {
        val jwk = EcPublicJsonWebKey(
            curve = JwkEllipticCurve.P256,
            xCoordinate = "test-x",
            yCoordinate = "test-y",
            keyUse = JwkKeyUse.SIGNATURE,
            algorithm = JwsAlgorithm.ES256,
            keyId = "ec-public"
        )

        assertEquals(JwkKeyType.EC, jwk.keyType)
        assertTrue(jwk.isPublicKey)
        assertFalse(jwk.isPrivateKey)
        assertEquals(JwkEllipticCurve.P256, jwk.curve)
        assertEquals("test-x", jwk.xCoordinate)
        assertEquals("test-y", jwk.yCoordinate)
    }

    @Test
    fun testEcPrivateKey() {
        val jwk = EcPrivateJsonWebKey(
            curve = JwkEllipticCurve.P256,
            xCoordinate = "test-x",
            yCoordinate = "test-y",
            privateKey = "test-private-key",
            keyUse = JwkKeyUse.SIGNATURE,
            algorithm = JwsAlgorithm.ES256,
            keyId = "ec-private"
        )

        assertEquals(JwkKeyType.EC, jwk.keyType)
        assertFalse(jwk.isPublicKey)
        assertTrue(jwk.isPrivateKey)
        assertEquals("test-private-key", jwk.privateKey)
    }

    @Test
    fun testSymmetricKey() {
        val jwk = SymmetricJsonWebKey(
            keyValue = "test-key-value",
            keyUse = JwkKeyUse.SIGNATURE,
            algorithm = JwsAlgorithm.HS256,
            keyId = "symmetric"
        )

        assertEquals(JwkKeyType.SYMMETRIC, jwk.keyType)
        assertFalse(jwk.isPublicKey)
        assertTrue(jwk.isPrivateKey)
        assertEquals("test-key-value", jwk.keyValue)
    }

    @Test
    fun testTypeChecking() {
        val rsaPublic: JsonWebKey = RsaPublicJsonWebKey(
            modulus = "test-modulus",
            exponent = "AQAB"
        )

        val rsaPrivate: JsonWebKey = RsaPrivateJsonWebKey(
            modulus = "test-modulus",
            exponent = "AQAB",
            privateExponent = "test-private"
        )

        val ecPublic: JsonWebKey = EcPublicJsonWebKey(
            curve = JwkEllipticCurve.P256,
            xCoordinate = "test-x",
            yCoordinate = "test-y"
        )

        val symmetric: JsonWebKey = SymmetricJsonWebKey(
            keyValue = "test-key"
        )

        // Test RSA type checking
        assertTrue(rsaPublic is RsaJsonWebKey)
        assertTrue(rsaPublic is RsaPublicJsonWebKey)
        assertFalse(rsaPublic is RsaPrivateJsonWebKey)

        assertTrue(rsaPrivate is RsaJsonWebKey)
        assertTrue(rsaPrivate is RsaPrivateJsonWebKey)
        assertFalse(rsaPrivate is RsaPublicJsonWebKey)

        // Test EC type checking
        assertTrue(ecPublic is EcJsonWebKey)
        assertTrue(ecPublic is EcPublicJsonWebKey)

        // Test symmetric type checking
        assertTrue(symmetric is SymmetricJsonWebKey)
        assertFalse(symmetric is RsaJsonWebKey)
        assertFalse(symmetric is EcJsonWebKey)
    }

    @Test
    fun testJwkSetOperations() {
        val rsaKey = RsaPublicJsonWebKey(
            modulus = "test-modulus",
            exponent = "AQAB",
            keyUse = JwkKeyUse.SIGNATURE,
            algorithm = JwsAlgorithm.RS256,
            keyId = "key-1"
        )

        val ecKey = EcPublicJsonWebKey(
            curve = JwkEllipticCurve.P256,
            xCoordinate = "test-x",
            yCoordinate = "test-y",
            keyUse = JwkKeyUse.ENCRYPTION,
            algorithm = JwsAlgorithm.ES256,
            keyId = "key-2"
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

        // Test type-specific finders
        val rsaKeysTyped = jwkSet.findRsaKeys()
        assertEquals(1, rsaKeysTyped.size)
        assertTrue(rsaKeysTyped.first() is RsaPublicJsonWebKey)

        val ecKeysTyped = jwkSet.findEcKeys()
        assertEquals(1, ecKeysTyped.size)
        assertTrue(ecKeysTyped.first() is EcPublicJsonWebKey)

        val symmetricKeys = jwkSet.findSymmetricKeys()
        assertEquals(0, symmetricKeys.size)
    }
}
