/*
 * Copyright (c) 2024-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.bigint

import kotlin.math.*
import kotlin.random.*
import kotlin.test.*

class BigIntArrayTest {

    @Test
    fun testEmptyArray() {
        assertFails { byteArrayOf().decodeToBigInt() }
    }

    @Test
    fun testZeroArrays() {
        listOf(
            byteArrayOf(0),
            byteArrayOf(0, 0, 0),
            ByteArray(10000)
        ).forEach {
            val bigInt = it.decodeToBigInt()
            assertEquals(BigInt.ZERO, bigInt)
            assertEquals("0", bigInt.toString())
            assertContentEquals(byteArrayOf(0), bigInt.encodeToByteArray())
        }
    }

    @Test
    fun testRandomArrays() {
        fun test(pow: Int) {
            val array = Random.nextBytes(10.0.pow(pow).toInt())
            val bigIntFromHex = array.decodeToBigInt()
            val string = bigIntFromHex.toString()
            val hex = bigIntFromHex.toHexString()
            checkBigInt(bigIntFromHex, string, hex)
        }

        repeat(100) { test(2) }
        repeat(1000) { test(3) }
        repeat(50) { test(4) }
    }
}
