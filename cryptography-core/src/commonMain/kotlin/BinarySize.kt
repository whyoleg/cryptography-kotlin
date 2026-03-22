/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography

import kotlin.jvm.*

/**
 * Represents a binary size as a number of bits, with conversions to bytes.
 *
 * Used throughout the API for key sizes, tag sizes, IV sizes, salt sizes, etc.
 * Values must be non-negative and a multiple of 8 (byte-aligned).
 *
 * Use the extension properties [BinarySize.Companion.bits] and [BinarySize.Companion.bytes] to create instances: `256.bits` or `32.bytes`.
 */
@JvmInline
public value class BinarySize private constructor(private val bits: Int) : Comparable<BinarySize> {
    init {
        require(bits >= 0) { "Value must be greater than or equal to 0" }
        require(bits % 8 == 0) { "Value must be a multiple of 8" }
    }

    /**
     * The value expressed as a number of bits.
     */
    public val inBits: Int get() = bits

    /**
     * The value expressed as a number of bytes (bits divided by 8).
     */
    public val inBytes: Int get() = bits / 8

    public operator fun plus(other: BinarySize): BinarySize = BinarySize(bits + other.bits)
    public operator fun minus(other: BinarySize): BinarySize = BinarySize(bits - other.bits)
    public operator fun times(other: Int): BinarySize = BinarySize(bits * other)
    public operator fun div(other: Int): BinarySize = BinarySize(bits / other)
    public operator fun rem(other: Int): BinarySize = BinarySize(bits % other)
    public override operator fun compareTo(other: BinarySize): Int = bits.compareTo(other.bits)

    override fun toString(): String = "$bits bits"

    public companion object {
        /**
         * Returns a [BinarySize] treating this integer as a number of bits.
         *
         * For example, `256.bits` represents a 256-bit (32-byte) value.
         */
        public val Int.bits: BinarySize get() = BinarySize(this)

        /**
         * Returns a [BinarySize] treating this integer as a number of bytes.
         *
         * For example, `32.bytes` represents a 32-byte (256-bit) value.
         */
        public val Int.bytes: BinarySize get() = BinarySize(this * 8)
    }
}
