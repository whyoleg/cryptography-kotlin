/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.bits

public fun BitSet(size: Int): BitSet = TODO()
public fun BitSet(size: Int, initializer: (Int) -> Boolean): BitSet = TODO()
public fun BitSet(bitString: BitString): BitSet = TODO()

// it's like ByteArray
// automatically resizable?
// copyOf/copyOfRange/copyInto?
public class BitSet private constructor(
    // number of bits
    public val size: Int,
    dummy: Any?,
) {
    public operator fun get(index: Int): Boolean = TODO()

    public operator fun set(index: Int, value: Boolean) {}
    public fun set(fromIndex: Int, toIndex: Int, value: Boolean) {}
    public operator fun set(indexes: IntRange, value: Boolean) {}

    public fun set(index: Int) {}
    public fun set(fromIndex: Int, toIndex: Int) {}
    public fun set(indexes: IntRange) {}

    public fun flip(index: Int) {}
    public fun flip(fromIndex: Int, toIndex: Int) {}
    public fun flip(indexes: IntRange) {}

    public fun clear(index: Int) {}
    public fun clear(fromIndex: Int, toIndex: Int) {}
    public fun clear(indexes: IntRange) {}

    public fun getBitString(startIndex: Int = 0, endIndex: Int = size): BitString = TODO()
    public fun toBitString(): BitString = TODO() // save as getByteString(0, size)

    // prints a list of set bits?
    // BitSet([1, 5, 12])
    override fun toString(): String {
        return super.toString()
    }
}
