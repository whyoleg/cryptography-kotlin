/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.bigint

import kotlin.math.*

@OptIn(ExperimentalUnsignedTypes::class)
public actual class BigInt internal constructor(
    public actual val sign: Int,
    internal val magnitude: UIntArray,
) : Number(), Comparable<BigInt> {
    public actual companion object {
        public actual val ZERO: BigInt = BigInt(0, uintArrayOf(0U))
    }

    init {
        // just checking if everything works fine internally
        check(sign == sign.sign) { "wrong sign: $sign" }
        check(magnitude.isNotEmpty()) { "empty magnitude" }
        if (sign == 0) check(magnitude.size == 1 && magnitude[0] == 0U) { "zero sign and not array(0)" }
    }

    public actual operator fun compareTo(other: Byte): Int = compareTo(other.toBigInt())
    public actual operator fun compareTo(other: Short): Int = compareTo(other.toBigInt())
    public actual operator fun compareTo(other: Int): Int = compareTo(other.toBigInt())
    public actual operator fun compareTo(other: Long): Int = compareTo(other.toBigInt())
    public actual override fun compareTo(other: BigInt): Int {
        fun compareTo(a: UIntArray, b: UIntArray): Int {
            a.size.compareTo(b.size).let {
                if (it != 0) return it
            }
            repeat(a.size) { i ->
                a[i].compareTo(b[i]).let {
                    if (it != 0) return it
                }
            }
            return 0
        }

        return when {
            sign != other.sign -> sign.compareTo(other.sign)
            sign == 1          -> compareTo(magnitude, other.magnitude)
            sign == -1         -> compareTo(other.magnitude, magnitude)
            else               -> 0
        }
    }

    public actual override fun toByte(): Byte = toInt().toByte()
    public actual override fun toShort(): Short = toInt().toShort()
    public actual override fun toInt(): Int = magnitude.last().toInt() * sign
    public actual override fun toLong(): Long = when (val size = magnitude.size) {
        1    -> magnitude[0].toLong()
        else -> {
            val highInt = magnitude[size - 2]
            val lowInt = magnitude[size - 1]
            ((highInt.toULong() shl 32) + lowInt.toULong()).toLong()
        }
    } * sign

    public actual override fun toFloat(): Float = toString().toFloat()
    public actual override fun toDouble(): Double = toString().toDouble()

    public actual override fun toString(): String {
        if (sign == 0) return "0"

        val chunks = ArrayDeque<String>()

        var magnitude = this.magnitude.copyOf()
        while (true) {
            var rem = 0UL
            repeat(magnitude.size) { index ->
                val value = (rem shl 32) + magnitude[index]
                // replace value in place
                magnitude[index] = (value / CHUNK_MULTIPLIER).toUInt()
                rem = value % CHUNK_MULTIPLIER
            }
            magnitude = magnitude.removeLeadingZeros()

            if (magnitude.isNotEmpty()) {
                chunks.addFirst(rem.toString().padStart(CHUNK_SIZE, '0'))
            } else {
                chunks.addFirst(rem.toString())
                break
            }
        }
        return chunks.joinToString(
            separator = "",
            prefix = when (sign) {
                -1   -> "-"
                else -> ""
            }
        )
    }

    public actual override fun hashCode(): Int = magnitude.contentHashCode() * sign

    public actual override fun equals(other: Any?): Boolean = when {
        this === other                            -> true
        other !is BigInt                          -> false
        sign != other.sign                        -> false
        !magnitude.contentEquals(other.magnitude) -> false
        else                                      -> true
    }
}

public actual fun Byte.toBigInt(): BigInt = toInt().toBigInt()
public actual fun Short.toBigInt(): BigInt = toInt().toBigInt()

@OptIn(ExperimentalUnsignedTypes::class)
public actual fun Int.toBigInt(): BigInt = when (this) {
    0    -> BigInt.ZERO
    else -> BigInt(
        sign = sign,
        magnitude = uintArrayOf(absoluteValue.toUInt())
    )
}

@OptIn(ExperimentalUnsignedTypes::class)
public actual fun Long.toBigInt(): BigInt = when (this) {
    0L   -> BigInt.ZERO
    else -> {
        val abs = absoluteValue
        BigInt(
            sign = sign,
            magnitude = when (val high = (abs ushr 32).toInt()) {
                0    -> uintArrayOf(abs.toUInt())
                else -> uintArrayOf(high.toUInt(), abs.toUInt())
            }
        )
    }
}

public actual fun UByte.toBigInt(): BigInt = toInt().toBigInt()
public actual fun UShort.toBigInt(): BigInt = toInt().toBigInt()

@OptIn(ExperimentalUnsignedTypes::class)
public actual fun UInt.toBigInt(): BigInt = when (this) {
    0U   -> BigInt.ZERO
    else -> BigInt(
        sign = 1,
        magnitude = uintArrayOf(this)
    )
}

@OptIn(ExperimentalUnsignedTypes::class)
public actual fun ULong.toBigInt(): BigInt = when (this) {
    0UL  -> BigInt.ZERO
    else -> BigInt(
        sign = 1,
        magnitude = when (val high = (this shr 32).toInt()) {
            0    -> uintArrayOf(toUInt())
            else -> uintArrayOf(high.toUInt(), toUInt())
        }
    )
}

@OptIn(ExperimentalUnsignedTypes::class)
public actual fun String.toBigInt(): BigInt {

    // returns carry
    fun UIntArray.multiplyAndAdd(index: Int, multiplier: ULong, addition: ULong): ULong {
        val sum = multiplier * this[index] + addition
        this[index] = sum.toUInt()
        return sum shr 32
    }

    fun UIntArray.multiplyAndAdd(chunk: ULong) {
        var carry = 0UL

        repeat(size) { i -> carry = multiplyAndAdd(size - 1 - i, CHUNK_MULTIPLIER, carry) }

        check(carry == 0UL) { "carry.1=$carry" }

        carry = multiplyAndAdd(size - 1, 1UL, chunk)

        repeat(size - 1) { i -> carry = multiplyAndAdd(size - 2 - i, 1UL, carry) }

        check(carry == 0UL) { "carry.2=$carry" }
    }

    require(isNotEmpty()) { "String is empty" }

    val sign = if (this[0] == '-') -1 else 1
    var stringIndex = when (this[0]) {
        '-'  -> 1
        '+'  -> 1
        else -> 0
    }

    require(stringIndex != length) { "String contains only `sign`" }

    // remove leading zeros
    while (this[stringIndex] == '0' && stringIndex < length - 1) stringIndex += 1

    if (stringIndex == length) return BigInt.ZERO

    val numberOfDigits = length - stringIndex
    val firstChunkSize = when (val value = numberOfDigits % CHUNK_SIZE) {
        0    -> CHUNK_SIZE
        else -> value
    }

    val magnitude = UIntArray(numberOfDigits / CHUNK_SIZE + 1)
    magnitude[magnitude.size - 1] = substring(stringIndex, stringIndex + firstChunkSize).toUInt()
    stringIndex += firstChunkSize
    while (stringIndex != length) {
        magnitude.multiplyAndAdd(substring(stringIndex, stringIndex + CHUNK_SIZE).toULong())
        stringIndex += CHUNK_SIZE
    }
    val result = magnitude.removeLeadingZeros()
    if (result.isEmpty()) return BigInt.ZERO
    return BigInt(sign, result)
}

public actual fun String.toBigIntOrNull(): BigInt? = try {
    toBigInt()
} catch (cause: Throwable) {
    null
}

@OptIn(ExperimentalUnsignedTypes::class)
public actual fun ByteArray.decodeToBigInt(): BigInt {
    require(isNotEmpty()) { "empty array" }

    if (size == 1 && this[0] == 0.toByte()) return BigInt.ZERO
    val sign = if (this[0] < 0) -1 else 1
    // not used when sign < 0
    val bytes = copyOf().invertTwoComplementIfNeeded(sign)
    val magnitude = UIntArray(size / 4 + 1)

    repeat(bytes.size) {
        val byteIndex = bytes.size - 1 - it
        val intIndex = magnitude.size - 1 - it / 4
        val shiftedByte = bytes[byteIndex].toUInt() and 0xFFU shl (it % 4) * 8
        magnitude[intIndex] += shiftedByte
    }

    val result = magnitude.removeLeadingZeros()
    if (result.isEmpty()) return BigInt.ZERO
    return BigInt(sign, result)
}

// TODO - rewrite
@OptIn(ExperimentalUnsignedTypes::class)
public actual fun BigInt.encodeToByteArray(): ByteArray {
    inline fun ByteArray.uint(byteCount: Int, byteOffset: Int, value: UInt) {
        repeat(byteCount) { this[byteOffset + it] = (value shr (byteCount - 1 - it) * 8).toByte() }
    }

    if (sign == 0) return byteArrayOf(0)

    val bytes = ByteArray(magnitude.size * 4 - (magnitude[0].countLeadingZeroBits() / 8)).also { bytes ->
        var currentInt = 0U
        repeat(bytes.size) {
            val byteIndex = bytes.size - 1 - it
            val byteInIntIndex = it % 4
            if (byteInIntIndex == 0) {
                val intIndex = magnitude.size - 1 - it / 4
                currentInt = magnitude[intIndex]
            }
            val currentByte = (currentInt shr (byteInIntIndex) * 8).toByte()
            bytes[byteIndex] = currentByte
        }
    }.invertTwoComplementIfNeeded(sign)

    val positive = sign > 0
    val firstBytePositive = bytes[0] >= 0
    if (positive == firstBytePositive) return bytes

    // prepend sign byte
    return ByteArray(bytes.size + 1).also {
        it[0] = if (positive) 0 else -1
        bytes.copyInto(it, 1)
    }
}

// inline
@OptIn(ExperimentalUnsignedTypes::class)
private fun UIntArray.removeLeadingZeros(): UIntArray {
    return when (val index = indexOfFirst { it != 0U }) {
        -1   -> EmptyUIntArray
        0    -> this
        else -> copyOfRange(index, size)
    }
}

// Int.MAX_VALUE is 10 digits, so 9 can fit full number
private const val CHUNK_SIZE: Int = 9

// 9 zeros
private const val CHUNK_MULTIPLIER: ULong = 1_000_000_000UL

@OptIn(ExperimentalUnsignedTypes::class)
private val EmptyUIntArray: UIntArray = uintArrayOf()

// works in place
private fun ByteArray.invertTwoComplementIfNeeded(sign: Int): ByteArray {
    if (sign > 0) return this

    val firstNonZeroFromEnd = indexOfLast { it != 0.toByte() }

    repeat(size) { index ->
        val negated = this[index].toInt().inv()
        this[index] = when {
            index < firstNonZeroFromEnd -> negated
            else                        -> negated + 1
        }.toByte()
    }

    return this
}
