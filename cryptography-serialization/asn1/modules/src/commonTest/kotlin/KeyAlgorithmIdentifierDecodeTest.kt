/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.modules

import dev.whyoleg.cryptography.serialization.asn1.*
import kotlinx.serialization.decodeFromByteArray
import kotlin.test.*

class KeyAlgorithmIdentifierDecodeTest {

    private fun String.hexToBytes(): ByteArray {
        check(length % 2 == 0) { "Invalid hex length" }
        return ByteArray(length / 2) { i ->
            val hi = this[i * 2].digitToInt(16)
            val lo = this[i * 2 + 1].digitToInt(16)
            ((hi shl 4) or lo).toByte()
        }
    }

    @Test
    fun decode_Ed25519_absentParameters() {
        // SEQUENCE { algorithm OBJECT IDENTIFIER 1.3.101.112 } (no parameters element)
        val bytes = "300506032B6570".hexToBytes()
        val id = Der.decodeFromByteArray<KeyAlgorithmIdentifier>(bytes)
        assertTrue(id is UnknownKeyAlgorithmIdentifier)
        assertEquals(ObjectIdentifier.Ed25519, id.algorithm)
    }

    @Test
    fun decode_Ed25519_nullParameters() {
        // SEQUENCE { algorithm OBJECT IDENTIFIER 1.3.101.112, parameters NULL }
        val bytes = "300706032B65700500".hexToBytes()
        val id = Der.decodeFromByteArray<KeyAlgorithmIdentifier>(bytes)
        assertTrue(id is UnknownKeyAlgorithmIdentifier)
        assertEquals(ObjectIdentifier.Ed25519, id.algorithm)
    }

    @Test
    fun decode_X25519_absentParameters() {
        // SEQUENCE { algorithm OBJECT IDENTIFIER 1.3.101.110 } (no parameters element)
        val bytes = "300506032B656E".hexToBytes()
        val id = Der.decodeFromByteArray<KeyAlgorithmIdentifier>(bytes)
        assertTrue(id is UnknownKeyAlgorithmIdentifier)
        assertEquals(ObjectIdentifier.X25519, id.algorithm)
    }

    @Test
    fun decode_X25519_nullParameters() {
        // SEQUENCE { algorithm OBJECT IDENTIFIER 1.3.101.110, parameters NULL }
        val bytes = "300706032B656E0500".hexToBytes()
        val id = Der.decodeFromByteArray<KeyAlgorithmIdentifier>(bytes)
        assertTrue(id is UnknownKeyAlgorithmIdentifier)
        assertEquals(ObjectIdentifier.X25519, id.algorithm)
    }

    @Test
    fun decode_Ed448_absentParameters() {
        val bytes = "300506032B6571".hexToBytes()
        val id = Der.decodeFromByteArray<KeyAlgorithmIdentifier>(bytes)
        assertTrue(id is UnknownKeyAlgorithmIdentifier)
        assertEquals(ObjectIdentifier.Ed448, id.algorithm)
    }

    @Test
    fun decode_Ed448_nullParameters() {
        val bytes = "300706032B65710500".hexToBytes()
        val id = Der.decodeFromByteArray<KeyAlgorithmIdentifier>(bytes)
        assertTrue(id is UnknownKeyAlgorithmIdentifier)
        assertEquals(ObjectIdentifier.Ed448, id.algorithm)
    }

    @Test
    fun decode_X448_absentParameters() {
        val bytes = "300506032B6570".replace("70","6F").hexToBytes() // 1.3.101.111
        val id = Der.decodeFromByteArray<KeyAlgorithmIdentifier>(bytes)
        assertTrue(id is UnknownKeyAlgorithmIdentifier)
        assertEquals(ObjectIdentifier.X448, id.algorithm)
    }

    @Test
    fun decode_X448_nullParameters() {
        val bytes = "300706032B656F0500".hexToBytes()
        val id = Der.decodeFromByteArray<KeyAlgorithmIdentifier>(bytes)
        assertTrue(id is UnknownKeyAlgorithmIdentifier)
        assertEquals(ObjectIdentifier.X448, id.algorithm)
    }
}
