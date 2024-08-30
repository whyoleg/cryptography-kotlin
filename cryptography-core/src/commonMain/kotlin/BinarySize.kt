/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography

import kotlin.jvm.*

@JvmInline
public value class BinarySize private constructor(private val bits: Int) : Comparable<BinarySize> {
    init {
        require(bits >= 0) { "Value must be greater than or equal to 0" }
        require(bits % 8 == 0) { "Value must be a multiple of 8" }
    }

    public val inBits: Int get() = bits
    public val inBytes: Int get() = bits / 8

    public operator fun plus(other: BinarySize): BinarySize = BinarySize(bits + other.bits)
    public operator fun minus(other: BinarySize): BinarySize = BinarySize(bits - other.bits)
    public operator fun times(other: Int): BinarySize = BinarySize(bits * other)
    public operator fun div(other: Int): BinarySize = BinarySize(bits / other)
    public operator fun rem(other: Int): BinarySize = BinarySize(bits % other)
    public override operator fun compareTo(other: BinarySize): Int = bits.compareTo(other.bits)

    override fun toString(): String = "$bits bits"

    public companion object {
        public val Int.bits: BinarySize get() = BinarySize(this)
        public val Int.bytes: BinarySize get() = BinarySize(this * 8)
    }
}
