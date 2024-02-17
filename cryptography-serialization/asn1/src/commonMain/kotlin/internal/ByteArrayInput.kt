/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.internal

private val emptyArray = ByteArray(0)

internal class ByteArrayInput(
    private val array: ByteArray,
    startIndex: Int = 0,
    private val endIndex: Int = array.size,
) {
    private var position: Int = startIndex
    private val available: Int get() = endIndex - position
    val eof: Boolean get() = available == 0

    override fun toString(): String {
        return "ByteArrayInput(size=${array.size}, endIndex=$endIndex, position=$position, available=$available)"
    }

    fun peak(): Byte {
        ensureAvailableBytes(1)
        return array[position]
    }

    fun read(): Byte {
        ensureAvailableBytes(1)
        return array[position++]
    }

    fun read(length: Int): ByteArray {
        ensureAvailableBytes(length)

        if (length == 0) return emptyArray
        return array.copyOfRange(
            fromIndex = position,
            toIndex = position + length
        ).also {
            position += length
        }
    }

    fun readSlice(length: Int): ByteArrayInput {
        ensureAvailableBytes(length)

        if (length == 0) return ByteArrayInput(emptyArray)
        return ByteArrayInput(
            array = array,
            startIndex = position,
            endIndex = position + length
        ).also {
            position += length
        }
    }

    private fun ensureAvailableBytes(count: Int) {
        check(available >= count) { "Unexpected EOF, available $available bytes, requested: $count" }
    }
}
