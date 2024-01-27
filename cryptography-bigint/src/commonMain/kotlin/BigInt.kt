/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

@file:JvmMultifileClass
@file:JvmName("BigIntKt")

package dev.whyoleg.cryptography.bigint

import kotlin.jvm.*

public expect class BigInt : Number, Comparable<BigInt> {
    public companion object {
        public val ZERO: BigInt
    }

    public val sign: Int

    // from `Comparable`
    public operator fun compareTo(other: Byte): Int
    public operator fun compareTo(other: Short): Int
    public operator fun compareTo(other: Int): Int
    public operator fun compareTo(other: Long): Int
    public override operator fun compareTo(other: BigInt): Int

    // from `Number`
    public override fun toByte(): Byte
    public override fun toShort(): Short
    public override fun toInt(): Int
    public override fun toLong(): Long
    public override fun toFloat(): Float
    public override fun toDouble(): Double

    // from `Any`
    public override fun toString(): String
    public override fun hashCode(): Int
    public override fun equals(other: Any?): Boolean
}

public expect fun Byte.toBigInt(): BigInt
public expect fun Short.toBigInt(): BigInt
public expect fun Int.toBigInt(): BigInt
public expect fun Long.toBigInt(): BigInt

public expect fun UByte.toBigInt(): BigInt
public expect fun UShort.toBigInt(): BigInt
public expect fun UInt.toBigInt(): BigInt
public expect fun ULong.toBigInt(): BigInt

public fun BigInt.toUByte(): UByte = toByte().toUByte()
public fun BigInt.toUShort(): UShort = toShort().toUShort()
public fun BigInt.toUInt(): UInt = toInt().toUInt()
public fun BigInt.toULong(): ULong = toLong().toULong()

public expect fun String.toBigInt(): BigInt
public expect fun String.toBigIntOrNull(): BigInt?

// two's complement
public expect fun ByteArray.decodeToBigInt(): BigInt
public expect fun BigInt.encodeToByteArray(): ByteArray
