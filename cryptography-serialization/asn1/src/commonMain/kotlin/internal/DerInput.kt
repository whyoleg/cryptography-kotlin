/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.internal

import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.serialization.asn1.*

internal class DerInput(private val input: ByteArrayInput) {
    val eof: Boolean get() = input.eof

    fun peakTag(): DerTag = input.peak()

    fun isNotNull(): Boolean = peakTag() != DerTag_NULL

    fun readNull(): Nothing? {
        input.readRequestedTag(DerTag_NULL)

        val length = input.readLength()
        check(length == 0) { "NULL tag length should be zero, but was: $length" }
        return null
    }

    fun readInteger(tagOverride: ContextSpecificTag?): BigInt = input.readTagWithOverride(tagOverride, DerTag_INTEGER) {
        val length = readLength()
        val bytes = read(length)
        bytes.decodeToBigInt()
    }

    fun readBitString(tagOverride: ContextSpecificTag?): BitArray = input.readTagWithOverride(tagOverride, DerTag_BIT_STRING) {
        val length = readLength()
        val unusedBits = read().toInt()
        val bytes = read(length - 1)

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

        BitArray(unusedBits, bytes)
    }

    fun readOctetString(tagOverride: ContextSpecificTag?): ByteArray = input.readTagWithOverride(tagOverride, DerTag_OCTET_STRING) {
        val length = readLength()
        read(length)
    }

    fun readObjectIdentifier(tagOverride: ContextSpecificTag?): ObjectIdentifier = input.readTagWithOverride(tagOverride, DerTag_OID) {
        val length = readLength()
        val slice = readSlice(length)
        ObjectIdentifier(slice.readOidElements())
    }

    fun readSequence(tagOverride: ContextSpecificTag?): ByteArrayInput = input.readTagWithOverride(tagOverride, DerTag_SEQUENCE) {
        val length = readLength()
        readSlice(length)
    }
}

private inline fun <T> ByteArrayInput.readTagWithOverride(
    tagOverride: ContextSpecificTag?,
    tag: DerTag,
    block: ByteArrayInput.() -> T,
): T {
    if (tagOverride == null) {
        readRequestedTag(tag)
        return block()
    }

    readRequestedTag(tagOverride.tag)
    return when (tagOverride.type) {
        ContextSpecificTag.TagType.IMPLICIT -> block()
        ContextSpecificTag.TagType.EXPLICIT -> {
            val length = readLength()
            val explicitInput = readSlice(length)
            explicitInput.readRequestedTag(tag)
            explicitInput.block()
        }
    }
}

private fun ByteArrayInput.readRequestedTag(tag: DerTag) {
    val currentTag = read()
    check(currentTag == tag) { "Requested tag '${DerTag_name(tag)}', received: '${DerTag_name(currentTag)}'" }
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
    check(element >= 0) { "element overflow: $element" }
    return element
}
