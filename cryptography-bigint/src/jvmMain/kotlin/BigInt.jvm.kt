/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

@file:JvmMultifileClass
@file:JvmName("BigIntKt")

package dev.whyoleg.cryptography.bigint

import java.math.*

public actual class BigInt internal constructor(
    @JvmField
    internal val javaBigInteger: BigInteger,
) : Number(), Comparable<BigInt> {
    public actual companion object {
        public actual val ZERO: BigInt = BigInt(BigInteger.ZERO)
    }

    public actual val sign: Int get() = javaBigInteger.signum()

    public actual operator fun compareTo(other: Byte): Int = compareTo(other.toBigInt())
    public actual operator fun compareTo(other: Short): Int = compareTo(other.toBigInt())
    public actual operator fun compareTo(other: Int): Int = compareTo(other.toBigInt())
    public actual operator fun compareTo(other: Long): Int = compareTo(other.toBigInt())
    public actual override operator fun compareTo(other: BigInt): Int = javaBigInteger.compareTo(other.javaBigInteger)

    public actual override fun toByte(): Byte = javaBigInteger.toByte()
    public actual override fun toShort(): Short = javaBigInteger.toShort()
    public actual override fun toInt(): Int = javaBigInteger.toInt()
    public actual override fun toLong(): Long = javaBigInteger.toLong()
    public actual override fun toFloat(): Float = javaBigInteger.toFloat()
    public actual override fun toDouble(): Double = javaBigInteger.toDouble()

    public actual override fun toString(): String = javaBigInteger.toString()
    public actual override fun hashCode(): Int = javaBigInteger.hashCode()
    public actual override fun equals(other: Any?): Boolean {
        if (other !is BigInt) return false
        return javaBigInteger == other.javaBigInteger
    }
}

public actual fun Byte.toBigInt(): BigInt = toLong().toBigInt()
public actual fun Short.toBigInt(): BigInt = toLong().toBigInt()
public actual fun Int.toBigInt(): BigInt = toLong().toBigInt()

public actual fun Long.toBigInt(): BigInt = when (this) {
    0L   -> BigInt.ZERO
    else -> BigInt(toBigInteger())
}

public actual fun UByte.toBigInt(): BigInt = toLong().toBigInt()
public actual fun UShort.toBigInt(): BigInt = toLong().toBigInt()
public actual fun UInt.toBigInt(): BigInt = toLong().toBigInt()

public actual fun ULong.toBigInt(): BigInt = when (this) {
    0UL  -> BigInt.ZERO
    else -> BigInt(toString().toBigInteger())
}

public actual fun String.toBigInt(): BigInt = BigInt(toBigInteger())
public actual fun String.toBigIntOrNull(): BigInt? = toBigIntegerOrNull()?.let(::BigInt)

public actual fun ByteArray.decodeToBigInt(): BigInt = BigInt(BigInteger(this))
public actual fun BigInt.encodeToByteArray(): ByteArray = javaBigInteger.toByteArray()

public fun BigInt.toJavaBigInteger(): BigInteger = javaBigInteger
public fun BigInteger.toKotlinBigInt(): BigInt = BigInt(this)
