/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1

import dev.whyoleg.cryptography.serialization.asn1.ContextSpecificTag.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromByteArray
import kotlin.test.*

class NegativeDecodingTest {

    @Test
    fun wrongTagForInteger() {
        // OCTET STRING (0x04) with one byte content 0x01
        val bytes = byteArrayOf(0x04, 0x01, 0x01).map { it.toByte() }.toByteArray()
        assertFailsWith<IllegalStateException> {
            Der.decodeFromByteArray<Int>(bytes)
        }
    }

    @Test
    fun invalidLengthZeroInLongForm() {
        // OID (0x06) with long-form length 0x82 0x00 0x00 -> illegal zero length
        val bytes = byteArrayOf(0x06, 0x82.toByte(), 0x00, 0x00).map { it.toByte() }.toByteArray()
        assertFailsWith<IllegalStateException> {
            Der.decodeFromByteArray<ObjectIdentifier>(bytes)
        }
    }

    @Serializable
    class MandatoryImplicit(
        @ContextSpecificTag(0, TagType.IMPLICIT)
        val x: Int,
    )

    @Test
    fun contextSpecificMandatoryTagMismatch() {
        // Encoded value only for tag [1] IMPLICIT with INTEGER 8
        val sequence = byteArrayOf(0x30, 0x03, 0x81.toByte(), 0x01, 0x08).map { it.toByte() }.toByteArray()
        assertFailsWith<IllegalStateException> {
            Der.decodeFromByteArray<MandatoryImplicit>(sequence)
        }
    }

    @Serializable
    class ExplicitInt(
        @ContextSpecificTag(0, TagType.EXPLICIT)
        val x: Int,
    )

    @Test
    fun contextSpecificExplicitInnerTagMismatch() {
        // SEQUENCE { [0] EXPLICIT { OCTET STRING 0x01 } } but Int expects INTEGER inside EXPLICIT
        val seq = byteArrayOf(
            0x30, 0x05,       // SEQUENCE, len 5
            0xA0.toByte(), 0x03, // [0] EXPLICIT, len 3
            0x04, 0x01, 0x01  // OCTET STRING, len 1, 0x01
        )
        assertFailsWith<IllegalStateException> {
            Der.decodeFromByteArray<ExplicitInt>(seq)
        }
    }

    @Test
    fun bitStringEmptyWithNonZeroUnusedBits() {
        // BIT STRING: length 1, unusedBits = 1, no payload
        val bs = byteArrayOf(0x03, 0x01, 0x01)
        assertFailsWith<IllegalStateException> {
            Der.decodeFromByteArray<BitArray>(bs)
        }
    }

    @Test
    fun bitStringUnusedBitsExceedsTrailingZeros() {
        // BIT STRING: unusedBits=1, payload last byte 0x01 (no trailing zeros)
        val bs = byteArrayOf(0x03, 0x02, 0x01, 0x01)
        assertFailsWith<IllegalStateException> {
            Der.decodeFromByteArray<BitArray>(bs)
        }
    }
}
