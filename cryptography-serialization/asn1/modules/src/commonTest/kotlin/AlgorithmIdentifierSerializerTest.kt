/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.serialization.asn1.*
import kotlinx.serialization.*
import kotlin.test.*

@OptIn(ExperimentalSerializationApi::class)
class AlgorithmIdentifierSerializerTest {

    @Test
    fun testRsaAlgorithmIdentifier() {
        val original: AlgorithmIdentifier = RsaAlgorithmIdentifier
        val bytes = Der.encodeToByteArray<AlgorithmIdentifier>(original)
        val decoded = Der.decodeFromByteArray<AlgorithmIdentifier>(bytes)

        assertTrue(decoded is RsaAlgorithmIdentifier)
        assertEquals(ObjectIdentifier.RSA, decoded.algorithm)
        assertNull(decoded.parameters)
    }

    @Test
    fun testEcAlgorithmIdentifier() {
        val original: AlgorithmIdentifier = EcAlgorithmIdentifier(EcParameters(ObjectIdentifier.secp256r1))
        val bytes = Der.encodeToByteArray<AlgorithmIdentifier>(original)
        val decoded = Der.decodeFromByteArray<AlgorithmIdentifier>(bytes)

        assertTrue(decoded is EcAlgorithmIdentifier)
        assertEquals(ObjectIdentifier.EC, decoded.algorithm)
        assertEquals(ObjectIdentifier.secp256r1, decoded.parameters?.namedCurve)
    }

    @Test
    fun testEcAlgorithmIdentifierWithDifferentCurves() {
        val curves = listOf(
            ObjectIdentifier.secp256r1,
            ObjectIdentifier.secp384r1,
            ObjectIdentifier.secp521r1
        )

        for (curve in curves) {
            val original: AlgorithmIdentifier = EcAlgorithmIdentifier(EcParameters(curve))
            val bytes = Der.encodeToByteArray<AlgorithmIdentifier>(original)
            val decoded = Der.decodeFromByteArray<AlgorithmIdentifier>(bytes)

            assertTrue(decoded is EcAlgorithmIdentifier, "Expected EcAlgorithmIdentifier for curve $curve")
            assertEquals(curve, decoded.parameters?.namedCurve, "Curve mismatch for $curve")
        }
    }

    @Test
    fun testUnknownAlgorithmIdentifierThrows() {
        // Create a custom serializer that only knows about EC
        val limitedSerializer = object : AlgorithmIdentifierSerializer() {
            init {
                algorithm(ObjectIdentifier.EC, ::EcAlgorithmIdentifier)
            }
        }

        // Encode RSA algorithm (which has no parameters) with default serializer
        val rsaBytes = Der.encodeToByteArray<AlgorithmIdentifier>(RsaAlgorithmIdentifier)

        // Decode with limited serializer - should throw for unknown algorithm
        assertFailsWith<IllegalStateException> {
            Der.decodeFromByteArray(limitedSerializer, rsaBytes)
        }
    }

    @Test
    fun testCustomSerializerWithExplicitParameterSerializer() {
        val customSerializer = object : AlgorithmIdentifierSerializer() {
            init {
                algorithm(ObjectIdentifier.RSA, RsaAlgorithmIdentifier, encodeNull = true)
                algorithm(ObjectIdentifier.EC, ::EcAlgorithmIdentifier)
            }
        }

        val original = EcAlgorithmIdentifier(EcParameters(ObjectIdentifier.secp384r1))
        val bytes = Der.encodeToByteArray(customSerializer, original)
        val decoded = Der.decodeFromByteArray(customSerializer, bytes)

        assertTrue(decoded is EcAlgorithmIdentifier)
        assertEquals(ObjectIdentifier.secp384r1, decoded.parameters?.namedCurve)
    }

    @Test
    fun testCustomSerializerWithFunctionReference() {
        val customSerializer = object : AlgorithmIdentifierSerializer() {
            init {
                algorithm(ObjectIdentifier.RSA, RsaAlgorithmIdentifier, encodeNull = true)
                algorithm(ObjectIdentifier.EC, ::EcAlgorithmIdentifier)
            }
        }

        val original = EcAlgorithmIdentifier(EcParameters(ObjectIdentifier.secp521r1))
        val bytes = Der.encodeToByteArray(customSerializer, original)
        val decoded = Der.decodeFromByteArray(customSerializer, bytes)

        assertTrue(decoded is EcAlgorithmIdentifier)
        assertEquals(ObjectIdentifier.secp521r1, decoded.parameters?.namedCurve)
    }

    @Test
    fun testCustomAlgorithmIdentifier() {
        // Define a custom algorithm identifier for testing
        val customOid = ObjectIdentifier("1.2.3.4.5")

        @Serializable
        class CustomParameters(val value: Int)

        class CustomAlgorithmIdentifier(
            override val parameters: CustomParameters?,
        ) : AlgorithmIdentifier {
            override val algorithm: ObjectIdentifier get() = customOid
        }

        val customSerializer = object : AlgorithmIdentifierSerializer() {
            init {
                algorithm(customOid, ::CustomAlgorithmIdentifier)
            }
        }

        val original = CustomAlgorithmIdentifier(CustomParameters(42))
        val bytes = Der.encodeToByteArray(customSerializer, original)
        val decoded = Der.decodeFromByteArray(customSerializer, bytes)

        assertTrue(decoded is CustomAlgorithmIdentifier)
        assertEquals(42, decoded.parameters?.value)
    }

}
