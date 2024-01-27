/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.bigint

import kotlin.test.*

fun checkBigInt(bigInt: BigInt, string: String, hex: String) {
    checkBigIntEncoding(bigInt, string, hex)
    checkString(string, hex)
}

@OptIn(ExperimentalStdlibApi::class)
fun checkString(string: String) {
    checkString(string, string.toBigInt().toHexString())
}

@OptIn(ExperimentalStdlibApi::class)
fun checkString(string: String, hex: String) {
    val bigIntFromString = string.toBigInt()
    val bigIntFromHex = hex.hexToBigInt()
    assertEquals(bigIntFromHex, bigIntFromString)
    assertEquals(bigIntFromHex.hashCode(), bigIntFromString.hashCode())
    checkBigIntEncoding(bigIntFromString, string, hex)
    checkBigIntEncoding(bigIntFromHex, string, hex)
}

fun checkString(string: String, hexPositive: String, hexNegative: String) {
    checkString(string, hexPositive)
    checkString("-$string", hexNegative)
}

fun <T> checkPrimitive(
    value: T,
    bigIntToPrimitive: BigInt.() -> T,
    primitiveToBigInt: T.() -> BigInt,
) {
    val string = value.toString()
    fun test(bigInt: BigInt) {
        assertEquals(value, bigInt.bigIntToPrimitive())
        assertEquals(string, bigInt.toString())
    }

    test(value.primitiveToBigInt())
    test(string.toBigInt())
}

@OptIn(ExperimentalStdlibApi::class)
private fun checkBigIntEncoding(value: BigInt, string: String, hex: String) {
    assertEquals(string, value.toString())
    assertEquals(hex, value.toHexString())
}

class NumberData(
    val value: Long,
    val string: String,
    val hex: String?,
    val bytes: ByteArray?,
)

fun checkNumber(
    value: Long,
    string: String,
    hex: String?,
    bytes: ByteArray?,
) = checkNumber(NumberData(value, string, hex, bytes))

@OptIn(ExperimentalStdlibApi::class)
fun checkNumber(data: NumberData) {
    listOfNotNull(
        data.value.toBigInt(),
        data.string.toBigInt(),
        data.hex?.hexToBigInt(),
        data.bytes?.decodeToBigInt()
    ).forEach {
        assertEquals(data.value, it.toLong())
        assertEquals(data.string, it.toString())
        assertEquals(data.hex, it.toHexString())
        assertContentEquals(data.bytes, it.encodeToByteArray())
    }
}