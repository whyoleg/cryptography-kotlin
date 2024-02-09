/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.internal

import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.serialization.asn1.*

internal class DerOutput(private val output: ByteArrayOutput) {
    fun writeNull() {
        output.writeTag(DerTag.NULL, 0)
    }

    fun writeInteger(value: BigInt) {
        writeTag(DerTag.INTEGER, value.encodeToByteArray())
    }

    fun writeBitString(bytes: ByteArray) {
        // TODO ?
        output.writeTag(DerTag.BIT_STRING, bytes.size + 1)
        output.write(bytes.last().countTrailingZeroBits())
        output.write(bytes)
    }

    fun writeOctetString(bytes: ByteArray) {
        writeTag(DerTag.OCTET_STRING, bytes)
    }

    fun writeObjectIdentifier(value: ObjectIdentifier) {
        val intermediate = ByteArrayOutput()
        val strings = value.value.split(".")
        intermediate.writeOidElements(IntArray(strings.size) { strings[it].toInt() })
        writeTag(DerTag.OID, intermediate)
    }

    fun writeSequence(bytes: ByteArrayOutput) {
        writeTag(DerTag.SEQUENCE, bytes)
    }

    private fun writeTag(tag: DerTag, bytes: ByteArray) {
        output.writeTag(tag, bytes.size)
        output.write(bytes)
    }

    private fun writeTag(tag: DerTag, bytes: ByteArrayOutput) {
        output.writeTag(tag, bytes.size)
        output.write(bytes)
    }
}

private fun ByteArrayOutput.writeTag(tag: DerTag, length: Int) {
    write(tag.value)
    writeLength(length)
}

private fun ByteArrayOutput.writeLength(length: Int) {
    if (length < 128) return write(length)

    val l = Int.SIZE_BYTES - length.countLeadingZeroBits() / 8
    write(l or 0b10000000)
    repeat(l) { write(length shr 8 * (l - 1 - it)) }
}

// TODO: add checks
private fun ByteArrayOutput.writeOidElements(elements: IntArray) {
    check(elements.size >= 2)

    write(elements[0] * 40 + elements[1])
    repeat(elements.size - 2) { writeOidElement(elements[it + 2]) }
}

private fun ByteArrayOutput.writeOidElement(element: Int) {
    if (element < 128) return write(element)

    // TODO: recheck l
    val l = (Int.SIZE_BITS - element.countLeadingZeroBits()) / 7
    repeat(l) { write(((element shr (l - it) * 7) and 0b01111111) or 0b10000000) }
    write(element and 0b01111111)
}
