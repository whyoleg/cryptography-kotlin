/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.bigint

import kotlin.random.*
import kotlin.test.*

class BigIntPrimitiveTest {

    @Test
    fun testUnaryPlus() {
        assertEquals(123.toBigInt(), +123.toBigInt())
        assertEquals(BigInt.ZERO, +BigInt.ZERO)
        assertEquals((-123).toBigInt(), +(-123).toBigInt())
    }

    @Test
    fun testUnaryMinus() {
        assertEquals((-123).toBigInt(), -123.toBigInt())
        assertEquals(BigInt.ZERO, -BigInt.ZERO)
        assertEquals(123.toBigInt(), -(-123).toBigInt())
        assertEquals("-999999999999999999999999999999".toBigInt(), -"999999999999999999999999999999".toBigInt())
    }

    @Test
    fun testUnaryMinusRoundtrip() {
        val values = listOf(0, 1, -1, 127, -128, 65537, Int.MAX_VALUE, Int.MIN_VALUE + 1)
        values.forEach { v ->
            val bigInt = v.toBigInt()
            assertEquals(bigInt, -(-bigInt))
        }
    }

    @Test
    fun testSigns() {
        assertEquals(1, 123.toBigInt().sign)
        assertEquals(0, 0.toBigInt().sign)
        assertEquals(-1, (-123).toBigInt().sign)
        assertEquals(1, "123".toBigInt().sign)
        assertEquals(0, "0".toBigInt().sign)
        assertEquals(-1, "-123".toBigInt().sign)
    }

    @Test
    fun testZero() = checkNumber(
        value = 0,
        string = "0",
        hex = "00",
        bytes = byteArrayOf(0)
    )

    @Test
    fun testOne() = checkNumber(
        value = 1,
        string = "1",
        hex = "01",
        bytes = byteArrayOf(1)
    )

    @Test
    fun testMinusOne() = checkNumber(
        value = -1,
        string = "-1",
        hex = "ff",
        bytes = byteArrayOf(-1)
    )

    @Test
    fun testRsaExponent() = checkNumber(
        value = 65537,
        string = "65537",
        hex = "010001",
        bytes = byteArrayOf(1, 0, 1)
    )

    @Test
    fun testNumber1() = checkNumber(
        value = -1008114485,
        string = "-1008114485",
        hex = "c3e964cb",
        bytes = byteArrayOf(-61, -23, 100, -53)
    )

    @Test
    fun testNumber2() = checkNumber(
        value = -26079913583188396,
        string = "-26079913583188396",
        hex = "a35874ef19e654",
        bytes = byteArrayOf(-93, 88, 116, -17, 25, -26, 84)
    )

    @Test
    fun testMaxUnsignedByte() {
        val value = UByte.MAX_VALUE.toBigInt()
        assertEquals("255", value.toString())
        assertEquals("00ff", value.toHexString())
    }

    @Test
    fun testMaxUnsignedInt() {
        val value = UInt.MAX_VALUE.toBigInt()
        assertEquals("4294967295", value.toString())
        assertEquals("00ffffffff", value.toHexString())
    }

    @Test
    fun testMaxUnsignedLong() {
        val value = ULong.MAX_VALUE.toBigInt()
        assertEquals("18446744073709551615", value.toString())
        assertEquals("00ffffffffffffffff", value.toHexString())
    }

    @Test
    fun testMaxUnsignedByteNegative() {
        val value = (-255).toBigInt()
        assertEquals("-255", value.toString())
        assertEquals("ff01", value.toHexString())
    }

    @Test
    fun testMaxUnsignedIntNegative() {
        val value = (-4294967295).toBigInt()
        assertEquals("-4294967295", value.toString())
        assertEquals("ff00000001", value.toHexString())
    }

    @Test
    fun testMaxUnsignedLongNegative() {
        val value = "-18446744073709551615".toBigInt()
        assertEquals("ff0000000000000001", value.toHexString())
    }

    @Test
    fun testConversion() {
        val number = "10000000000000000011000000020000000230".toBigInt()
        assertEquals(-7378004098569484058, number.toLong())
        assertEquals(11068739975140067558U, number.toULong())
        assertEquals(-647771930, number.toInt())
        assertEquals(3647195366U, number.toUInt())
        assertEquals(-14106, number.toShort())
        assertEquals(51430U, number.toUShort())
        assertEquals(-26, number.toByte())
        assertEquals(230U, number.toUByte())
    }

    @Test
    fun testAllByte() {
        (Byte.MIN_VALUE..Byte.MAX_VALUE).forEach {
            checkPrimitive(it.toByte(), BigInt::toByte, Byte::toBigInt)
        }
    }

    @Test
    fun testAllUByte() {
        (UByte.MIN_VALUE..UByte.MAX_VALUE).forEach {
            checkPrimitive(it.toUByte(), BigInt::toUByte, UByte::toBigInt)
        }
    }

    @Test
    fun testAllShort() {
        (Short.MIN_VALUE..Short.MAX_VALUE).forEach {
            checkPrimitive(it.toShort(), BigInt::toShort, Short::toBigInt)
        }
    }

    @Test
    fun testAllUShort() {
        (UShort.MIN_VALUE..UShort.MAX_VALUE).forEach {
            checkPrimitive(it.toUShort(), BigInt::toUShort, UShort::toBigInt)
        }
    }

    @Test
    fun testRandomInt() {
        repeat(100000) {
            checkPrimitive(Random.nextInt(), BigInt::toInt, Int::toBigInt)
        }
    }

    @Test
    fun testRandomUInt() {
        repeat(100000) {
            checkPrimitive(Random.nextUInt(), BigInt::toUInt, UInt::toBigInt)
        }
    }

    @Test
    fun testRandomLong() {
        repeat(10000) {
            checkPrimitive(Random.nextLong(), BigInt::toLong, Long::toBigInt)
        }
    }

    @Test
    fun testRandomULong() {
        repeat(10000) {
            checkPrimitive(Random.nextULong(), BigInt::toULong, ULong::toBigInt)
        }
    }

    @Test
    fun testPowerOfTwo() {
        // powers of two
        repeat(Int.SIZE_BITS) {
            val b = "1".padStart(Int.SIZE_BITS - it, '0').padEnd(Int.SIZE_BITS, '0')
            val value = b.toUInt(2).toInt()
            assertEquals(value, value.toBigInt().toInt())
            assertEquals(value.toString(), value.toBigInt().toString())
        }
        repeat(Long.SIZE_BITS) {
            val b = "1".padStart(Long.SIZE_BITS - it, '0').padEnd(Long.SIZE_BITS, '0')
            val value = b.toULong(2).toLong()
            assertEquals(value, value.toBigInt().toLong())
            assertEquals(value.toString(), value.toBigInt().toString())
        }
    }

    @Test
    fun testAll1Bits() {
        repeat(Int.SIZE_BITS) {
            val b = "1".repeat(Int.SIZE_BITS)
            val value = b.toUInt(2).toInt()
            assertEquals(value, value.toBigInt().toInt())
            assertEquals(value.toString(), value.toBigInt().toString())
        }
        repeat(Long.SIZE_BITS) {
            val b = "1".repeat(Long.SIZE_BITS)
            val value = b.toULong(2).toLong()
            assertEquals(value, value.toBigInt().toLong())
            assertEquals(value.toString(), value.toBigInt().toString())
        }
    }
}
