/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.bigint

import kotlinx.serialization.*

@Serializable(with = BigIntAsStringSerializer::class)
public actual class BigInt internal constructor(
    internal val jsBigInt: JsBigInt,
) : Number(), Comparable<BigInt> {
    public actual companion object {
        public actual val ZERO: BigInt = BigInt(jsBigInt(0))
    }

    public actual val sign: Int get() = jsBigIntSign(jsBigInt)

    public actual operator fun compareTo(other: Byte): Int = compareTo(other.toBigInt())
    public actual operator fun compareTo(other: Short): Int = compareTo(other.toBigInt())
    public actual operator fun compareTo(other: Int): Int = compareTo(other.toBigInt())
    public actual operator fun compareTo(other: Long): Int = compareTo(other.toBigInt())
    public actual override operator fun compareTo(other: BigInt): Int = jsBigIntCompareTo(jsBigInt, other.jsBigInt)

    public actual override fun toByte(): Byte = jsBigIntAsInt(jsBigInt, 8).convertToString().toByte()
    public actual override fun toShort(): Short = jsBigIntAsInt(jsBigInt, 16).convertToString().toShort()
    public actual override fun toInt(): Int = jsBigIntAsInt(jsBigInt, 32).convertToString().toInt()
    public actual override fun toLong(): Long = jsBigIntAsInt(jsBigInt, 64).convertToString().toLong()
    public actual override fun toFloat(): Float = toString().toFloat()
    public actual override fun toDouble(): Double = toString().toDouble()

    public actual override fun toString(): String = jsBigInt.convertToString()

    // 36 is the max supported value, just to reduce the size of the string to compute hash
    public actual override fun hashCode(): Int = jsBigInt.convertToString(36).hashCode()

    public actual override fun equals(other: Any?): Boolean {
        if (other !is BigInt) return false
        return jsBigIntEquals(jsBigInt, other.jsBigInt)
    }
}

public actual fun Byte.toBigInt(): BigInt = toInt().toBigInt()
public actual fun Short.toBigInt(): BigInt = toInt().toBigInt()

public actual fun Int.toBigInt(): BigInt = when (this) {
    0    -> BigInt.ZERO
    else -> BigInt(jsBigInt(this))
}

public actual fun Long.toBigInt(): BigInt = when (this) {
    0L   -> BigInt.ZERO
    else -> BigInt(jsBigInt(toString()))
}

public actual fun UByte.toBigInt(): BigInt = toInt().toBigInt()
public actual fun UShort.toBigInt(): BigInt = toInt().toBigInt()

public actual fun UInt.toBigInt(): BigInt = when (this) {
    0U   -> BigInt.ZERO
    else -> BigInt(jsBigInt(toString()))
}

public actual fun ULong.toBigInt(): BigInt = when (this) {
    0UL  -> BigInt.ZERO
    else -> BigInt(jsBigInt(toString()))
}

public actual fun String.toBigInt(): BigInt {
    check(isNotBlank()) { "empty or blank string" }
    return BigInt(jsBigInt(this))
}

public actual fun String.toBigIntOrNull(): BigInt? {
    if (isBlank()) return null

    return try {
        BigInt(jsBigInt(this))
    } catch (cause: Throwable) {
        return null
    }
}

@OptIn(ExperimentalStdlibApi::class)
public actual fun ByteArray.decodeToBigInt(): BigInt {
    require(isNotEmpty()) { "empty array" }
    if (size == 1 && this[0] == 0.toByte()) return BigInt.ZERO

    val positive = this[0] >= 0

    val jsBigInt = when {
        positive -> jsBigInt("0x" + toHexString())
        else     -> jsBigIntNegate(jsBigInt("0x" + copyOf().invertTwoComplement().toHexString()))
    }

    return BigInt(jsBigInt)
}

@OptIn(ExperimentalStdlibApi::class)
public actual fun BigInt.encodeToByteArray(): ByteArray {
    // missing zero byte
    fun String.decodeFromHex(): ByteArray = (if (length % 2 == 0) this else "0$this").hexToByteArray()

    val positive = this >= 0

    val bytes = when {
        positive -> jsBigInt.convertToString(16).decodeFromHex()
        else     -> jsBigIntNegate(jsBigInt).convertToString(16).decodeFromHex().invertTwoComplement()
    }

    val firstBytePositive = bytes[0] >= 0
    if (positive == firstBytePositive) return bytes

    // prepend sign byte
    return ByteArray(bytes.size + 1).also {
        it[0] = if (positive) 0 else -1
        bytes.copyInto(it, 1)
    }
}

// works in place
private fun ByteArray.invertTwoComplement(): ByteArray {
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
