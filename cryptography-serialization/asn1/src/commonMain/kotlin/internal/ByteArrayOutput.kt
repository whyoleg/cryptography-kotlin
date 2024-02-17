/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.internal

internal class ByteArrayOutput {
    private var array: ByteArray = ByteArray(32)
    private var position: Int = 0

    val size: Int get() = position

    private fun ensureCapacity(elementsToAppend: Int) {
        if (position + elementsToAppend <= array.size) return

        array = array.copyOf((position + elementsToAppend).takeHighestOneBit() shl 1)
    }

    fun toByteArray(): ByteArray = array.copyOf(position)

    fun write(byte: Byte) {
        ensureCapacity(1)
        array[position++] = byte
    }

    fun write(byte: Int) {
        write(byte.toByte())
    }

    fun write(bytes: ByteArray) {
        if (bytes.isEmpty()) return

        ensureCapacity(bytes.size)
        bytes.copyInto(array, position)
        position += bytes.size
    }

    fun write(output: ByteArrayOutput) {
        if (output.size == 0) return

        ensureCapacity(output.position)
        output.array.copyInto(array, position, 0, output.position)
        position += output.position
    }
}
