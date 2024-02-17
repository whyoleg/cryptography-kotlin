/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.internal

import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.serialization.asn1.*

internal class DerInput(private val input: ByteArrayInput) {
    val eof: Boolean get() = input.eof

    fun isNotNull(): Boolean {
        return input.peak() != DerTag_NULL
    }

    fun readNull(): Nothing? {
        val length = input.readTagLength(DerTag_NULL)
        check(length == 0) { "NULL tag length should be zero, but was: $length" }
        return null
    }

    fun readInteger(): BigInt {
        return input.readTagBytes(DerTag_INTEGER).decodeToBigInt()
    }

    fun readBitString(): BitArray {
        val length = input.readTagLength(DerTag_BIT_STRING)
        val unusedBits = input.read().toInt()
        val bytes = input.read(length - 1)

        when {
            bytes.isEmpty() -> check(unusedBits == 0) {
                "wrong number of unused bits, expected 0, received: $unusedBits"
            }
            // in DER unused bits should be all zero
            else            -> {
                val trailingZeros = bytes.last().countTrailingZeroBits()
                check(unusedBits <= trailingZeros) {
                    "Not all unused bits are zeros, expected at least $unusedBits trailing zeros, received $trailingZeros"
                }
            }
        }

        return BitArray(unusedBits, bytes)
    }

    fun readOctetString(): ByteArray {
        return input.readTagBytes(DerTag_OCTET_STRING)
    }

    fun readObjectIdentifier(): ObjectIdentifier {
        return ObjectIdentifier(input.readTagSlice(DerTag_OID).readOidElements())
    }

    fun readSequence(): ByteArrayInput {
        return input.readTagSlice(DerTag_SEQUENCE)
    }

}

private fun ByteArrayInput.readTagLength(tag: DerTag): Int {
    val currentTag = read()
    check(currentTag == tag) { "Requested tag '$tag', received: '${name(currentTag)}'" }

    return readLength()
}

private fun ByteArrayInput.readTagBytes(tag: DerTag): ByteArray {
    return read(readTagLength(tag))
}

private fun ByteArrayInput.readTagSlice(tag: DerTag): ByteArrayInput {
    return readSlice(readTagLength(tag))
}

private fun ByteArrayInput.readLength(): Int {
    val first = read().toInt()
    // if negative, this means that significant bit is set
    if (first >= 0) return first
    val numberOfLengthBytes = first and 0b01111111

    // we support length only of Int size
    check(numberOfLengthBytes <= Int.SIZE_BYTES) { "Supported number of bytes for tag length are in range 1..4, but was: $numberOfLengthBytes " }

    var length = 0
    repeat(numberOfLengthBytes) { length = (length shl 8) + (read().toInt() and 0b11111111) }
    check(length > 0) { "length overflow: $length" }
    return length
}

private fun ByteArrayInput.readOidElements(): String = buildString {
    // 0.(0..<40) = 0..<40
    // 1.(0..<40) = 40..<80
    // 2.(0..XXX) = 80..XXX+80
    val first = readOidElement()
    when {
        first < 40 -> append('0').append('.').append(first)
        first < 80 -> append('1').append('.').append(first - 40)
        else       -> append('2').append('.').append(first - 80)
    }

    while (!eof) append('.').append(readOidElement())
}

private fun ByteArrayInput.readOidElement(): Int {
    var element = 0
    do {
        val b = read().toInt()
        element = (element shl 7) + (b and 0b01111111)
    } while (b and 0b10000000 == 0b10000000)
    check(element > 0) { "element overflow: $element" }
    return element
}
