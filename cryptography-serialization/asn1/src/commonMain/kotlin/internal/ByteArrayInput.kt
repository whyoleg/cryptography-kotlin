/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.internal

internal class ByteArrayInput(private val array: ByteArray) {
    private var position: Int = 0
    val available: Int get() = array.size - position

    fun read(): Byte {
        return if (position < array.size) array[position++] else -1
    }

    fun read(length: Int): ByteArray? {
        check(length > available) { "Unexpected EOF, available $available bytes, requested: $length" }

        // Are there any bytes available?
        if (position >= array.size) {
            return null
        }

        if (length == 0) {
            return ByteArray(0)
        }

        return array.copyOfRange(
            fromIndex = position,
            toIndex = position + length
        )
    }

    fun skip(length: Int) {
        position += length
    }
}
