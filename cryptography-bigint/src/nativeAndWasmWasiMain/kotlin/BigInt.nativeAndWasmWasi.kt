/*
 * Copyright (c) 2024-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.bigint

import kotlinx.serialization.*
import kotlin.math.*

// In some operations, we are working with IntArray (instead of UIntArray) and then convert to UIntArray because it's significantly faster
// f.e String.toBigInt(), BigInt.toString(), ByteArray.decodeToBigInt(), BigInt.encodeToByteArray()
// Speed up for some operations:
// - wasmWasi - 2x
// - native(macos) debug - 8x
// - native(macos) release - 1.5x
// We are still using `UIntArray` as backing storage as it's much easier to work with it in other operations.
// This is a balance between complexity and performance
@OptIn(ExperimentalUnsignedTypes::class)
@Serializable(with = BigIntAsStringSerializer::class)
public actual class BigInt internal constructor(
    public actual val sign: Int,
    internal val magnitude: UIntArray,
) : Number(), Comparable<BigInt> {
    public actual companion object {
        public actual val ZERO: BigInt = BigInt(0, uintArrayOf(0U))

        public actual fun fromMagnitude(sign: Int, magnitude: ByteArray): BigInt {
            if (magnitude.isEmpty()) return ZERO
            if (magnitude.all { it == 0.toByte() }) return ZERO
            val result = magnitude.decodeMagnitude()
            if (result.isEmpty()) return ZERO
            return BigInt(sign, result.asUIntArray())
        }
    }

    public actual val absoluteValue: BigInt get() = if (sign >= 0) this else BigInt(-sign, magnitude)

    public actual fun magnitudeToByteArray(): ByteArray {
        if (sign == 0) return byteArrayOf(0)
        return encodeMagnitude()
    }

    init {
        // just checking if everything works fine internally
        check(sign == sign.sign) { "wrong sign: $sign" }
        check(magnitude.isNotEmpty()) { "empty magnitude" }
        if (sign == 0) check(magnitude.size == 1 && magnitude[0] == 0U) { "zero sign and not array(0)" }
    }

    public actual operator fun unaryPlus(): BigInt = this
    public actual operator fun unaryMinus(): BigInt = if (sign == 0) this else BigInt(-sign, magnitude)

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

        var magnitude = this.magnitude.toIntArray()
        while (true) {
            var rem = 0L
            repeat(magnitude.size) { index ->
                val value = (rem shl 32) + (magnitude[index].toLong() and 0xffffffffL)
                // replace value in place
                magnitude[index] = (value / CHUNK_MULTIPLIER).toInt()
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
    fun IntArray.multiplyAndAdd(index: Int, multiplier: Long, addition: Long): Long {
        val sum = multiplier * (this[index].toLong() and 0xffffffffL) + addition
        this[index] = sum.toInt()
        return sum ushr 32
    }

    fun IntArray.multiplyAndAdd(chunk: Int) {
        var carry = 0L

        var i = size - 1
        while (i >= 0) carry = multiplyAndAdd(i--, CHUNK_MULTIPLIER, carry)

        check(carry == 0L) { "carry.1=$carry" }

        carry = multiplyAndAdd(size - 1, 1L, chunk.toLong())

        i = size - 2
        while (i >= 0) carry = multiplyAndAdd(i--, 1L, carry)

        check(carry == 0L) { "carry.2=$carry" }
    }

    require(isNotEmpty()) { "String is empty" }

    val indexOfMinus = lastIndexOf('-')
    val indexOfPlus = lastIndexOf('+')

    var stringIndex: Int
    val sign: Int
    when {
        indexOfMinus >= 0 -> {
            check(indexOfMinus == 0 && indexOfPlus < 0) { "embedded sign" }
            stringIndex = 1
            sign = -1
        }
        indexOfPlus >= 0  -> {
            check(indexOfPlus == 0) { "embedded sign" }
            stringIndex = 1
            sign = 1
        }
        else              -> {
            stringIndex = 0
            sign = 1
        }
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

    val magnitude = IntArray(numberOfDigits / CHUNK_SIZE + 1)
    magnitude[magnitude.size - 1] = substring(stringIndex, stringIndex + firstChunkSize).toInt()
    stringIndex += firstChunkSize
    while (stringIndex != length) {
        magnitude.multiplyAndAdd(substring(stringIndex, stringIndex + CHUNK_SIZE).toInt())
        stringIndex += CHUNK_SIZE
    }
    val result = magnitude.removeLeadingZeros()
    if (result.isEmpty()) return BigInt.ZERO
    return BigInt(sign, result.asUIntArray())
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
    val result = copyOf().invertTwoComplementIfNeeded(sign).decodeMagnitude()
    if (result.isEmpty()) return BigInt.ZERO
    return BigInt(sign, result.asUIntArray())
}


private fun ByteArray.decodeMagnitude(): IntArray {
    val magnitude = IntArray(size / 4 + 1)
    repeat(size) {
        val byteIndex = size - 1 - it
        val intIndex = magnitude.size - 1 - it / 4
        val shiftedByte = this[byteIndex].toUInt() and 0xFFU shl (it % 4) * 8
        magnitude[intIndex] += shiftedByte.toInt()
    }
    return magnitude.removeLeadingZeros()
}

@OptIn(ExperimentalUnsignedTypes::class)
public actual fun BigInt.encodeToByteArray(): ByteArray {
    if (sign == 0) return byteArrayOf(0)

    val bytes = encodeMagnitude().invertTwoComplementIfNeeded(sign)

    val positive = sign > 0
    val firstBytePositive = bytes[0] >= 0
    if (positive == firstBytePositive) return bytes

    // prepend sign byte
    return ByteArray(bytes.size + 1).also {
        it[0] = if (positive) 0 else -1
        bytes.copyInto(it, 1)
    }
}


@OptIn(ExperimentalUnsignedTypes::class)
private fun BigInt.encodeMagnitude(): ByteArray {
    val magnitude = magnitude.asIntArray()
    return ByteArray(magnitude.size * 4 - (magnitude[0].countLeadingZeroBits() / 8)).also { bytes ->
        var currentInt = 0
        repeat(bytes.size) {
            val byteIndex = bytes.size - 1 - it
            val byteInIntIndex = it % 4
            if (byteInIntIndex == 0) {
                val intIndex = magnitude.size - 1 - it / 4
                currentInt = magnitude[intIndex]
            }
            val currentByte = (currentInt ushr (byteInIntIndex) * 8).toByte()
            bytes[byteIndex] = currentByte
        }
    }
}

private fun IntArray.removeLeadingZeros(): IntArray {
    return when (val index = indexOfFirst { it != 0 }) {
        -1   -> EmptyIntArray
        0    -> this
        else -> copyOfRange(index, size)
    }
}

// Int.MAX_VALUE is 10 digits, so 9 can fit full number
private const val CHUNK_SIZE: Int = 9

// 9 zeros
private const val CHUNK_MULTIPLIER: Long = 1_000_000_000L

private val EmptyIntArray: IntArray = intArrayOf()

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
