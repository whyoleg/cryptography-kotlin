package dev.whyoleg.vio

import kotlin.jvm.*

@JvmInline
public value class BinarySize internal constructor(private val value: Int) {
    init {
        require(value >= 0) { "Value must be greater than or equal to 0" }
        require(value % 8 == 0) { "Value must be a multiple of 8" }

    }

    //TODO: rename it similar to like in Duration

    public val bits: Int get() = value
    public val bytes: Int get() = value / 8

    public operator fun plus(other: BinarySize): BinarySize = BinarySize(value + other.value)
    public operator fun minus(other: BinarySize): BinarySize = BinarySize(value - other.value)
    public operator fun compareTo(other: BinarySize): Int = value.compareTo(other.value)
}

public val Int.bits: BinarySize get() = BinarySize(this)
public val Int.bytes: BinarySize get() = BinarySize(this * 8)
