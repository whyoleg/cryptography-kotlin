/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.asn1.internal

import dev.whyoleg.cryptography.bigint.*
import dev.whyoleg.cryptography.serialization.asn1.*

internal class DerOutput(private val output: ByteArrayOutput) {
    fun writeNull() {
        output.write(DerTag_NULL)
        output.writeLength(0)
    }

    fun writeInteger(tagOverride: ContextSpecificTag?, value: BigInt) {
        output.writeTagWithOverride(tagOverride, DerTag_INTEGER) {
            writeBytes(value.encodeToByteArray())
        }
    }

    fun writeBitString(tagOverride: ContextSpecificTag?, bits: BitArray) {
        output.writeTagWithOverride(tagOverride, DerTag_BIT_STRING) {
            writeLength(bits.byteArray.size + 1)
            write(bits.unusedBits)
            write(bits.byteArray)
        }
    }

    fun writeOctetString(tagOverride: ContextSpecificTag?, bytes: ByteArray) {
        output.writeTagWithOverride(tagOverride, DerTag_OCTET_STRING) {
            writeBytes(bytes)
        }
    }

    fun writeObjectIdentifier(tagOverride: ContextSpecificTag?, value: ObjectIdentifier) {
        output.writeTagWithOverride(tagOverride, DerTag_OID) {
            writeBytes {
                writeOidElements(value.value.split("."))
            }
        }
    }

    fun writeSequence(tagOverride: ContextSpecificTag?, bytes: DerOutput) {
        output.writeTagWithOverride(tagOverride, DerTag_SEQUENCE) {
            writeBytes(bytes.output)
        }
    }

    fun writeAnyRaw(bytes: ByteArray) {
        // Write raw TLV bytes as-is
        output.write(bytes)
    }
}

private inline fun ByteArrayOutput.writeTagWithOverride(
    tagOverride: ContextSpecificTag?,
    tag: DerTag,
    block: ByteArrayOutput.() -> Unit,
) {
    if (tagOverride == null) {
        write(tag)
        block()
        return
    }

    write(tagOverride.tag)
    when (tagOverride.type) {
        ContextSpecificTag.TagType.IMPLICIT -> block()
        ContextSpecificTag.TagType.EXPLICIT -> writeBytes {
            write(tag)
            block()
        }
    }
}

private fun ByteArrayOutput.writeBytes(bytes: ByteArray) {
    writeLength(bytes.size)
    write(bytes)
}

private fun ByteArrayOutput.writeBytes(bytes: ByteArrayOutput) {
    writeLength(bytes.size)
    write(bytes)
}

private inline fun ByteArrayOutput.writeBytes(block: ByteArrayOutput.() -> Unit) {
    writeBytes(ByteArrayOutput().apply(block))
}

private fun ByteArrayOutput.writeLength(length: Int) {
    if (length < 128) return write(length)

    val numberOfLengthBytes = Int.SIZE_BYTES - length.countLeadingZeroBits() / 8
    write(numberOfLengthBytes or 0b10000000)
    repeat(numberOfLengthBytes) { write(length ushr 8 * (numberOfLengthBytes - 1 - it)) }
}

private fun ByteArrayOutput.writeOidElements(elements: List<String>) {
    check(elements.size >= 2) { "at least 2 components expected but was ${elements.size}" }
    fun element(index: Int): Int = elements[index].toInt()

    writeOidElement(element(0) * 40 + element(1))
    repeat(elements.size - 2) { writeOidElement(element(it + 2)) }
}

private fun ByteArrayOutput.writeOidElement(element: Int) {
    if (element < 128) return write(element)

    val l = (Int.SIZE_BITS - element.countLeadingZeroBits()) / 7
    repeat(l) {
        // zero should not be encoded
        val value = element ushr (l - it) * 7
        if (value != 0) write((value and 0b01111111) or 0b10000000)
    }
    write(element and 0b01111111)
}
