/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.bits

import kotlinx.serialization.*
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*

// it's like ByteString
// add more operations from ByteString
@Serializable(BitStringSerializer::class)
public class BitString private constructor() : Comparable<BitString> {
    public val size: Int get() = TODO()

    public operator fun get(index: Int): Boolean = TODO()

    public fun substring(startIndex: Int, endIndex: Int = size): BitString = TODO()

    public infix fun and(other: BitString): BitString = TODO()
    public infix fun or(other: BitString): BitString = TODO()
    public infix fun xor(other: BitString): BitString = TODO()

    public fun inv(): BitString = TODO()

    // other useful operations:
    // - shifts(?)
    // - intersect?
    // - cardinality?

    override fun compareTo(other: BitString): Int {
        TODO("Not yet implemented")
    }

    // equals, hashCode

    // prints "1010101000001111" - human readable, but long, still, will be probably used rarely
    override fun toString(): String {
        TODO("???")
    }

    // TODO: decide on conversions
    public fun toBooleanArray(): BooleanArray = TODO()
    public fun toByteArray(): ByteArray = TODO()
    public fun toLongArray(): LongArray = TODO() // representing as longs is the most compact way to store bit string

    // indexOf(true, startIndex)?
    // lastIndexOf(false, startIndex)?

    public companion object {
        // "011011010000"
        public fun parse(text: String): BitString = BitString()

        public fun fromBooleanArray(bits: BooleanArray): BitString = BitString()
        public fun fromByteArray(bytes: ByteArray, unusedBits: Int): BitString = BitString()
        public fun fromLongArray(words: LongArray, unusedBits: Int): BitString = BitString()
    }
}

internal object BitStringSerializer : KSerializer<BitString> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor(
        serialName = "dev.whyoleg.cryptography.bits.BitString",
        kind = PrimitiveKind.STRING
    )

    override fun serialize(encoder: Encoder, value: BitString) {
        encoder.encodeString(value.toString())
    }

    override fun deserialize(decoder: Decoder): BitString {
        return BitString.parse(decoder.decodeString())
    }
}
