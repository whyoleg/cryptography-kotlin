/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.internal

import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.serialization.asn1.*

internal class DerOutput(private val output: ByteArrayOutput) {
    fun writeNull() {
        output.writeTag(DerTag_NULL, 0)
    }

    fun writeInteger(value: BigInt) {
        output.writeTag(DerTag_INTEGER, value.encodeToByteArray())
    }

    fun writeBitString(bits: BitArray) {
        output.writeTag(DerTag_BIT_STRING, bits.byteArray.size + 1)
        output.write(bits.unusedBits)
        output.write(bits.byteArray)
    }

    fun writeOctetString(bytes: ByteArray) {
        output.writeTag(DerTag_OCTET_STRING, bytes)
    }

    fun writeObjectIdentifier(value: ObjectIdentifier) {
        val intermediate = ByteArrayOutput()
        val strings = value.value.split(".")
        intermediate.writeOidElements(strings)
        output.writeTag(DerTag_OID, intermediate)
    }

    fun writeSequence(bytes: DerOutput) {
        output.writeTag(DerTag_SEQUENCE, bytes.output)
    }

}

private fun ByteArrayOutput.writeTag(tag: DerTag, bytes: ByteArray) {
    writeTag(tag, bytes.size)
    write(bytes)
}

private fun ByteArrayOutput.writeTag(tag: DerTag, bytes: ByteArrayOutput) {
    writeTag(tag, bytes.size)
    write(bytes)
}

private fun ByteArrayOutput.writeTag(tag: DerTag, length: Int) {
    write(tag)
    writeLength(length)
}

private fun ByteArrayOutput.writeLength(length: Int) {
    if (length < 128) return write(length)

    val numberOfLengthBytes = Int.SIZE_BYTES - length.countLeadingZeroBits() / 8
    write(numberOfLengthBytes or 0b10000000)
    repeat(numberOfLengthBytes) { write(length ushr 8 * (numberOfLengthBytes - 1 - it)) }
}

// TODO: add checks
private fun ByteArrayOutput.writeOidElements(elements: List<String>) {
    check(elements.size >= 2) { "at least 2 components expected but was ${elements.size}" }
    fun element(index: Int): Int = elements[index].toInt()

    writeOidElement(element(0) * 40 + element(1))
    repeat(elements.size - 2) { writeOidElement(element(it + 2)) }
}

private fun ByteArrayOutput.writeOidElement(element: Int) {
    if (element < 128) return write(element)

    // TODO: recheck l
    val l = (Int.SIZE_BITS - element.countLeadingZeroBits()) / 7
    repeat(l) { write(((element ushr (l - it) * 7) and 0b01111111) or 0b10000000) }
    write(element and 0b01111111)
}
