/*
 * Copyright (c) 2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.bigint

import kotlin.random.*
import kotlin.test.*

class BigIntMagnitudeTest {

    // absoluteValue

    @Test
    fun testAbsoluteValuePositive() {
        val bigInt = 123.toBigInt()
        assertEquals(bigInt, bigInt.absoluteValue)
    }

    @Test
    fun testAbsoluteValueZero() {
        assertEquals(BigInt.ZERO, BigInt.ZERO.absoluteValue)
    }

    @Test
    fun testAbsoluteValueNegative() {
        assertEquals(123.toBigInt(), (-123).toBigInt().absoluteValue)
    }

    @Test
    fun testAbsoluteValueLargeNegative() {
        val large = "-999999999999999999999999999999".toBigInt()
        val expected = "999999999999999999999999999999".toBigInt()
        assertEquals(expected, large.absoluteValue)
    }

    // fromMagnitude

    @Test
    fun testFromMagnitudeEmpty() {
        assertEquals(BigInt.ZERO, BigInt.fromMagnitude(sign = 1, byteArrayOf()))
    }

    @Test
    fun testFromMagnitudeEmptyNegativeSign() {
        assertEquals(BigInt.ZERO, BigInt.fromMagnitude(sign = -1, byteArrayOf()))
    }

    @Test
    fun testFromMagnitudeZero() {
        assertEquals(BigInt.ZERO, BigInt.fromMagnitude(sign = 1, byteArrayOf(0)))
    }

    @Test
    fun testFromMagnitudeOne() {
        assertEquals(1.toBigInt(), BigInt.fromMagnitude(sign = 1, byteArrayOf(1)))
    }

    @Test
    fun testFromMagnitudeNegativeOne() {
        assertEquals((-1).toBigInt(), BigInt.fromMagnitude(sign = -1, byteArrayOf(1)))
    }

    @Test
    fun testFromMagnitudeHighBitSet() {
        // 0xFF as magnitude with positive sign = 255, not -1
        assertEquals(255.toBigInt(), BigInt.fromMagnitude(sign = 1, byteArrayOf(0xFF.toByte())))
    }

    @Test
    fun testFromMagnitude0x80() {
        // 0x80 as magnitude with positive sign = 128, not -128
        assertEquals(128.toBigInt(), BigInt.fromMagnitude(sign = 1, byteArrayOf(0x80.toByte())))
    }

    @Test
    fun testFromMagnitudeMultiByteHighBitSet() {
        // [0xFF, 0x01] as magnitude = 65281
        assertEquals(65281.toBigInt(), BigInt.fromMagnitude(sign = 1, byteArrayOf(0xFF.toByte(), 0x01)))
    }

    @Test
    fun testFromMagnitudeRsaExponent() {
        // 65537 = [0x01, 0x00, 0x01]
        assertEquals(65537.toBigInt(), BigInt.fromMagnitude(sign = 1, byteArrayOf(1, 0, 1)))
    }

    @Test
    fun testFromMagnitudeNegative() {
        assertEquals((-255).toBigInt(), BigInt.fromMagnitude(sign = -1, byteArrayOf(0xFF.toByte())))
    }

    // magnitudeToByteArray

    @Test
    fun testMagnitudeToByteArrayZero() {
        assertContentEquals(byteArrayOf(0), BigInt.ZERO.magnitudeToByteArray())
    }

    @Test
    fun testMagnitudeToByteArrayOne() {
        assertContentEquals(byteArrayOf(1), 1.toBigInt().magnitudeToByteArray())
    }

    @Test
    fun testMagnitudeToByteArray255() {
        // 255 magnitude = [0xFF], not [0x00, 0xFF] (no sign byte)
        assertContentEquals(byteArrayOf(0xFF.toByte()), 255.toBigInt().magnitudeToByteArray())
    }

    @Test
    fun testMagnitudeToByteArray128() {
        // 128 magnitude = [0x80], not [0x00, 0x80]
        assertContentEquals(byteArrayOf(0x80.toByte()), 128.toBigInt().magnitudeToByteArray())
    }

    @Test
    fun testMagnitudeToByteArray256() {
        // 256 = [0x01, 0x00]
        assertContentEquals(byteArrayOf(1, 0), 256.toBigInt().magnitudeToByteArray())
    }

    @Test
    fun testMagnitudeToByteArrayRsaExponent() {
        assertContentEquals(byteArrayOf(1, 0, 1), 65537.toBigInt().magnitudeToByteArray())
    }

    @Test
    fun testMagnitudeToByteArrayMaxUInt() {
        // UInt.MAX_VALUE = 4294967295 = [0xFF, 0xFF, 0xFF, 0xFF]
        val expected = byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte())
        assertContentEquals(expected, UInt.MAX_VALUE.toBigInt().magnitudeToByteArray())
    }

    @Test
    fun testMagnitudeToByteArrayNegative() {
        // magnitude of -255 is the same as magnitude of 255
        assertContentEquals(byteArrayOf(0xFF.toByte()), (-255).toBigInt().magnitudeToByteArray())
    }

    // roundtrip: fromMagnitude / magnitudeToByteArray

    @Test
    fun testMagnitudeRoundtrip() {
        val testCases = listOf(
            byteArrayOf(0),
            byteArrayOf(1),
            byteArrayOf(127),
            byteArrayOf(0x80.toByte()),
            byteArrayOf(0xFF.toByte()),
            byteArrayOf(1, 0),
            byteArrayOf(1, 0, 1),
            byteArrayOf(0xFF.toByte(), 0xFF.toByte()),
            byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte()),
        )

        testCases.forEach { bytes ->
            assertContentEquals(bytes, BigInt.fromMagnitude(sign = 1, bytes).magnitudeToByteArray())
        }
    }

    @Test
    fun testMagnitudeRoundtripRandom() {
        repeat(1000) {
            val bytes = Random.nextBytes(Random.nextInt(1, 100))
            // trim leading zeros for canonical form
            val trimmed = bytes.dropWhile { it == 0.toByte() }.toByteArray()
            val canonical = if (trimmed.isEmpty()) byteArrayOf(0) else trimmed
            assertContentEquals(canonical, BigInt.fromMagnitude(sign = 1, bytes).magnitudeToByteArray())
        }
    }

    // consistency: magnitude vs signed encoding

    @Test
    fun testMagnitudeVsSignedPositive() {
        // for values where MSB is not set, signed decode and fromMagnitude should give the same result
        val bytes = byteArrayOf(0x7F, 0x01)
        assertEquals(bytes.decodeToBigInt(), BigInt.fromMagnitude(sign = 1, bytes))
    }

    @Test
    fun testMagnitudeVsSignedDifference() {
        // for values where MSB is set, signed gives negative, magnitude with sign=1 gives positive
        val bytes = byteArrayOf(0xFF.toByte())
        assertEquals((-1).toBigInt(), bytes.decodeToBigInt())
        assertEquals(255.toBigInt(), BigInt.fromMagnitude(sign = 1, bytes))
    }

    @Test
    fun testMagnitudeVsSignedEncodeDifference() {
        // 255.encodeToByteArray() = [0x00, 0xFF] (two's complement, sign byte)
        // 255.magnitudeToByteArray() = [0xFF] (magnitude only, no sign byte)
        val bigInt = 255.toBigInt()
        assertContentEquals(byteArrayOf(0, 0xFF.toByte()), bigInt.encodeToByteArray())
        assertContentEquals(byteArrayOf(0xFF.toByte()), bigInt.magnitudeToByteArray())
    }
}
