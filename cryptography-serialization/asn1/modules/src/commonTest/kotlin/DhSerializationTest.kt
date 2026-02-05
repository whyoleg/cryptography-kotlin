/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.serialization.asn1.*
import kotlinx.serialization.*
import kotlin.test.*

class DhSerializationTest {

    @Test
    fun testDhParametersWithoutPrivateValueLength() {
        val original = DhParameters(
            prime = 23.toBigInt(),
            base = 5.toBigInt(),
        )

        val bytes = Der.encodeToByteArray<DhParameters>(original)
        val decoded = Der.decodeFromByteArray<DhParameters>(bytes)

        assertEquals(original.prime, decoded.prime)
        assertEquals(original.base, decoded.base)
        assertNull(decoded.privateValueLength)
    }

    @Test
    fun testDhParametersWithPrivateValueLength() {
        val original = DhParameters(
            prime = 23.toBigInt(),
            base = 5.toBigInt(),
            privateValueLength = 256,
        )

        val bytes = Der.encodeToByteArray<DhParameters>(original)
        val decoded = Der.decodeFromByteArray<DhParameters>(bytes)

        assertEquals(original.prime, decoded.prime)
        assertEquals(original.base, decoded.base)
        assertEquals(256, decoded.privateValueLength)
    }

    @Test
    fun testDhParametersWithLargePrime() {
        // A well-known 512-bit MODP prime from RFC 2409
        val prime =
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF"
                .hexToBigInt(HexFormat.UpperCase)
        val base = 2.toBigInt()

        val original = DhParameters(
            prime = prime,
            base = base,
        )

        val bytes = Der.encodeToByteArray<DhParameters>(original)
        val decoded = Der.decodeFromByteArray<DhParameters>(bytes)

        assertEquals(original.prime, decoded.prime)
        assertEquals(original.base, decoded.base)
        assertNull(decoded.privateValueLength)
    }

    @Test
    fun testDhAlgorithmIdentifierWithParameters() {
        val original: AlgorithmIdentifier = DhAlgorithmIdentifier(
            DhParameters(
                prime = 23.toBigInt(),
                base = 5.toBigInt(),
            )
        )

        val bytes = Der.encodeToByteArray<AlgorithmIdentifier>(original)
        val decoded = Der.decodeFromByteArray<AlgorithmIdentifier>(bytes)

        assertTrue(decoded is DhAlgorithmIdentifier)
        assertEquals(ObjectIdentifier.DH, decoded.algorithm)
        val parameters = assertNotNull(decoded.parameters)
        assertEquals(23.toBigInt(), parameters.prime)
        assertEquals(5.toBigInt(), parameters.base)
        assertNull(parameters.privateValueLength)
    }

    @Test
    fun testDhAlgorithmIdentifierWithPrivateValueLength() {
        val original: AlgorithmIdentifier = DhAlgorithmIdentifier(
            DhParameters(
                prime = 23.toBigInt(),
                base = 5.toBigInt(),
                privateValueLength = 128,
            )
        )

        val bytes = Der.encodeToByteArray<AlgorithmIdentifier>(original)
        val decoded = Der.decodeFromByteArray<AlgorithmIdentifier>(bytes)

        assertTrue(decoded is DhAlgorithmIdentifier)
        assertEquals(ObjectIdentifier.DH, decoded.algorithm)
        val parameters = assertNotNull(decoded.parameters)
        assertEquals(23.toBigInt(), parameters.prime)
        assertEquals(5.toBigInt(), parameters.base)
        assertEquals(128, parameters.privateValueLength)
    }

    @Test
    fun testDhAlgorithmIdentifierWithNullParameters() {
        val original: AlgorithmIdentifier = DhAlgorithmIdentifier(parameters = null)

        val bytes = Der.encodeToByteArray<AlgorithmIdentifier>(original)
        val decoded = Der.decodeFromByteArray<AlgorithmIdentifier>(bytes)

        assertTrue(decoded is DhAlgorithmIdentifier)
        assertEquals(ObjectIdentifier.DH, decoded.algorithm)
        assertNull(decoded.parameters)
    }
}
