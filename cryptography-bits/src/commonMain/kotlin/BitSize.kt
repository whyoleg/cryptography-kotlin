/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.bits

import kotlinx.serialization.*
import kotlin.jvm.*

// TODO: Long vs Int for all bits sizes
// TODO: check how `inline` will affect performance here
// TODO: may be we need `BitSizeRange` and co?
@Serializable
@JvmInline
public value class BitSize private constructor(
    private val bits: Int,
) : Comparable<BitSize> {

    public val inWholeBits: Int get() = bits
    public val inWholeBytes: Int get() = bits / 8

    public operator fun plus(other: BitSize): BitSize = BitSize(bits + other.bits)
    public operator fun minus(other: BitSize): BitSize = BitSize(bits - other.bits)

    public operator fun unaryMinus(): BitSize = BitSize(-bits)
    public operator fun unaryPlus(): BitSize = this

    public operator fun times(other: Int): BitSize = BitSize(bits * other)
    public operator fun div(other: Int): BitSize = BitSize(bits / other)
    public operator fun rem(other: Int): BitSize = BitSize(bits % other)

    public override operator fun compareTo(other: BitSize): Int = bits.compareTo(other.bits)

    override fun toString(): String = "$bits bits"

    public companion object {
        public val Int.bits: BitSize get() = BitSize(this)
        public val Int.bytes: BitSize get() = BitSize(this * 8)
    }
}
