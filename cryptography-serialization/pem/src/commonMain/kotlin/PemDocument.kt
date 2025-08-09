/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.pem

import kotlinx.io.*
import kotlinx.io.bytestring.*
import kotlinx.io.bytestring.unsafe.*
import kotlin.io.encoding.*

public class PemDocument(
    public val label: PemLabel,
    public val content: ByteString,
) {
    public constructor(
        label: PemLabel,
        content: ByteArray,
    ) : this(label, ByteString(content))

    public fun encodeToString(): String = encodeToByteArrayImpl().decodeToString()

    public fun encodeToByteArray(): ByteArray = encodeToByteArrayImpl()

    @OptIn(UnsafeByteStringApi::class)
    public fun encodeToByteString(): ByteString = UnsafeByteStringOperations.wrapUnsafe(encodeToByteArrayImpl())

    public fun encodeToSink(sink: Sink): Unit = sink.write(encodeToByteArrayImpl())

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PemDocument) return false

        if (label != other.label) return false
        if (content != other.content) return false

        return true
    }

    override fun hashCode(): Int {
        var result = label.hashCode()
        result = 31 * result + content.hashCode()
        return result
    }

    override fun toString(): String {
        return "PemDocument(label=$label, content=$content)"
    }

    public companion object {
        // decode will skip comments and everything else which is not label or content

        // will decode only the first one, even if there is something else after it
        public fun decode(text: String): PemDocument {
            return tryDecodeFromString(text, startIndex = 0, saveEndIndex = {}) ?: error("Invalid PEM format: missing BEGIN label")
        }

        public fun decodeToSequence(text: String): Sequence<PemDocument> = sequence {
            var startIndex = 0
            while (startIndex < text.length) {
                yield(tryDecodeFromString(text, startIndex) { startIndex = it } ?: break)
            }
            if (startIndex == 0) error("Invalid PEM format: missing BEGIN label")
        }

        @OptIn(UnsafeByteStringApi::class)
        public fun decode(bytes: ByteArray): PemDocument {
            return decode(UnsafeByteStringOperations.wrapUnsafe(bytes))
        }

        @OptIn(UnsafeByteStringApi::class)
        public fun decodeToSequence(bytes: ByteArray): Sequence<PemDocument> {
            return decodeToSequence(UnsafeByteStringOperations.wrapUnsafe(bytes))
        }

        public fun decode(bytes: ByteString): PemDocument {
            return tryDecodeFromByteString(bytes, startIndex = 0, saveEndIndex = {}) ?: error("Invalid PEM format: missing BEGIN label")
        }

        public fun decodeToSequence(bytes: ByteString): Sequence<PemDocument> = sequence {
            var startIndex = 0
            while (startIndex < bytes.size) {
                yield(tryDecodeFromByteString(bytes, startIndex) { startIndex = it } ?: break)
            }
            if (startIndex == 0) error("Invalid PEM format: missing BEGIN label")
        }

        public fun decode(source: Source): PemDocument {
            return tryDecodeFromSource(source) ?: error("Invalid PEM format: missing BEGIN label")
        }

        public fun decodeToSequence(source: Source): Sequence<PemDocument> = sequence {
            var hasAtLeastOneBeginLabel = false
            while (!source.exhausted()) {
                yield(tryDecodeFromSource(source) ?: break)
                hasAtLeastOneBeginLabel = true
            }
            if (!hasAtLeastOneBeginLabel) error("Invalid PEM format: missing BEGIN label")
        }
    }
}

private const val NEW_LINE = '\n'
private const val BEGIN_PREFIX = "-----BEGIN "
private const val END_PREFIX = "-----END "
private const val SUFFIX = "-----"

private const val NEW_LINE_BYTE = NEW_LINE.code.toByte()
private val BEGIN_BYTES = BEGIN_PREFIX.encodeToByteArray()
private val END_BYTES = END_PREFIX.encodeToByteArray()
private val SUFFIX_BYTES = SUFFIX.encodeToByteArray()

// Overall, the performance significantly depends on the target,
// some targets (wasmJs) may work with byte arrays faster, than with strings
// f.e tryDecodeFromByteString(text.encodeToByteArray) is faster than tryDecodeFromString(text) by 50%
// but hopefully it will be improved in the future
// on JVM, operations on byte arrays are always faster :)

// 1.5 times faster than naive encodeToString()
// 2 times faster than naive encodeToString().encodeToByteArray()
// naive encodeToString impl:
// return buildString {
//     append(BEGIN_PREFIX).append(label.value).appendLine(SUFFIX)
//     Base64.Pem.encodeToAppendable(content, this).appendLine()
//     append(END_PREFIX).append(label.value).appendLine(SUFFIX)
// }
private fun PemDocument.encodeToByteArrayImpl(): ByteArray {
    // based on kotlin.Base64 implementation
    fun base64EncodedSize(sourceSize: Int): Int {
        val groups = sourceSize / 3 //bytesPerGroup
        val trailingBytes = sourceSize % 3 // bytesPerGroup
        var size = groups * 4 // symbolsPerGroup
        if (trailingBytes != 0) { // trailing symbols
            size += 4
        }
        if (size < 0) { // Int overflow
            throw IllegalArgumentException("Input is too big")
        }
        size += ((size - 1) / 64) * 2
        if (size < 0) { // Int overflow
            throw IllegalArgumentException("Input is too big")
        }
        return size
    }

    val label = label.value.encodeToByteArray()
    val encodedSize = base64EncodedSize(content.size)

    val array = ByteArray(
        BEGIN_BYTES.size + label.size + SUFFIX_BYTES.size + 1 +
                encodedSize + 1 +
                END_BYTES.size + label.size + SUFFIX_BYTES.size + 1
    )

    // encode `-----BEGIN LABEL-----\n`
    BEGIN_BYTES.copyInto(array)
    label.copyInto(array, BEGIN_BYTES.size)
    SUFFIX_BYTES.copyInto(array, BEGIN_BYTES.size + label.size)
    array[BEGIN_BYTES.size + label.size + SUFFIX_BYTES.size] = NEW_LINE_BYTE

    // encode `base64\n`
    Base64.Pem.encodeIntoByteArray(content, array, BEGIN_BYTES.size + label.size + SUFFIX_BYTES.size + 1)
    array[BEGIN_BYTES.size + label.size + SUFFIX_BYTES.size + 1 + encodedSize] = NEW_LINE_BYTE

    // encode `-----END LABEL-----\n`
    END_BYTES.copyInto(array, BEGIN_BYTES.size + label.size + SUFFIX_BYTES.size + 1 + encodedSize + 1)
    label.copyInto(array, BEGIN_BYTES.size + label.size + SUFFIX_BYTES.size + 1 + encodedSize + 1 + END_BYTES.size)
    SUFFIX_BYTES.copyInto(array, BEGIN_BYTES.size + label.size + SUFFIX_BYTES.size + 1 + encodedSize + 1 + END_BYTES.size + label.size)
    array[array.lastIndex] = NEW_LINE_BYTE

    return array
}

// 1.5 times faster than using lineSequence()
private inline fun tryDecodeFromString(
    text: String,
    startIndex: Int,
    saveEndIndex: (endIndex: Int) -> Unit,
): PemDocument? {
    val beginIndex = text.indexOf(BEGIN_PREFIX, startIndex)
    if (beginIndex == -1) return null
    val beginLineEndIndex = text.indexOf(NEW_LINE, beginIndex + BEGIN_PREFIX.length)
    if (beginLineEndIndex == -1) error("Invalid PEM format: missing new line after BEGIN label")
    val beginSuffixIndex = text.indexOf(SUFFIX, beginIndex + BEGIN_PREFIX.length)
    if (beginSuffixIndex == -1 || beginSuffixIndex > beginLineEndIndex) error("Invalid PEM format: missing BEGIN label suffix")

    val beginLabel = text.substring(beginIndex + BEGIN_PREFIX.length, beginSuffixIndex)

    val endIndex = text.indexOf(END_PREFIX, beginLineEndIndex)
    if (endIndex == -1) error("Invalid PEM format: missing END label")
    val endLineEndIndex = text.indexOf(NEW_LINE, endIndex + END_PREFIX.length)
    val endSuffixIndex = text.indexOf(SUFFIX, endIndex + END_PREFIX.length)
    if (endSuffixIndex == -1 || (endLineEndIndex != -1 && endSuffixIndex > endLineEndIndex)) error("Invalid PEM format: missing END label suffix")

    val endLabel = text.substring(endIndex + END_PREFIX.length, endSuffixIndex)
    if (endLabel != beginLabel) error("Invalid PEM format: BEGIN=`$beginLabel`, END=`$endLabel`")

    saveEndIndex(
        if (endLineEndIndex == -1) {
            endSuffixIndex + SUFFIX.length
        } else {
            endLineEndIndex + 1
        }
    )
    return PemDocument(
        label = PemLabel(beginLabel),
        content = Base64.Pem.decodeToByteString(
            source = text,
            startIndex = beginLineEndIndex + 1, // 1 because of new line
            endIndex = endIndex
        )
    )
}

// 1.5 times faster than decode(bytes.decodeToString())
// 2 times faster than using lineSequence()
private inline fun tryDecodeFromByteString(
    bytes: ByteString,
    startIndex: Int,
    saveEndIndex: (endIndex: Int) -> Unit,
): PemDocument? {
    val beginIndex = bytes.indexOf(BEGIN_BYTES, startIndex)
    if (beginIndex == -1) return null
    val beginLineEndIndex = bytes.indexOf(NEW_LINE_BYTE, beginIndex + BEGIN_BYTES.size)
    if (beginLineEndIndex == -1) error("Invalid PEM format: missing new line after BEGIN label")
    val beginSuffixIndex = bytes.indexOf(SUFFIX_BYTES, beginIndex + BEGIN_BYTES.size)
    if (beginSuffixIndex == -1 || beginSuffixIndex > beginLineEndIndex) error("Invalid PEM format: missing BEGIN label suffix")

    val beginLabel = bytes.substring(beginIndex + BEGIN_BYTES.size, beginSuffixIndex)

    val endIndex = bytes.indexOf(END_BYTES, beginLineEndIndex)
    if (endIndex == -1) error("Invalid PEM format: missing END label")
    val endLineEndIndex = bytes.indexOf(NEW_LINE_BYTE, endIndex + END_BYTES.size)
    val endSuffixIndex = bytes.indexOf(SUFFIX_BYTES, endIndex + END_BYTES.size)
    if (endSuffixIndex == -1 || (endLineEndIndex != -1 && endSuffixIndex > endLineEndIndex)) error("Invalid PEM format: missing END label suffix")

    val endLabel = bytes.substring(endIndex + END_BYTES.size, endSuffixIndex)
    if (endLabel != beginLabel) error("Invalid PEM format: BEGIN=`${beginLabel.decodeToString()}`, END=`${endLabel.decodeToString()}`")

    saveEndIndex(
        if (endLineEndIndex == -1) {
            endSuffixIndex + SUFFIX_BYTES.size

        } else {
            endLineEndIndex + 1
        }
    )

    return PemDocument(
        label = PemLabel(beginLabel.decodeToString()),
        content = Base64.Pem.decodeToByteString(
            source = bytes,
            startIndex = beginLineEndIndex + 1, // 1 because of new line
            endIndex = endIndex
        )
    )
}

// 2 times faster than using lineSequence()
@OptIn(UnsafeByteStringApi::class)
private fun tryDecodeFromSource(source: Source): PemDocument? {
    fun Source.indexOf(bytes: ByteArray, startIndex: Long = 0): Long {
        return indexOf(UnsafeByteStringOperations.wrapUnsafe(bytes), startIndex)
    }

    val beginIndex = source.indexOf(BEGIN_BYTES)
    if (beginIndex == -1L) {
        // we haven't found BEGIN label, but we already read everything - discard it
        source.transferTo(discardingSink())
        return null
    }
    source.skip(beginIndex + BEGIN_BYTES.size)

    val beginLineEndIndex = source.indexOf(NEW_LINE_BYTE)
    if (beginLineEndIndex == -1L) error("Invalid PEM format: missing new line after BEGIN label")
    val beginSuffixIndex = source.indexOf(SUFFIX_BYTES)
    if (beginSuffixIndex == -1L || beginSuffixIndex > beginLineEndIndex) error("Invalid PEM format: missing BEGIN label suffix")

    val beginLabel = source.readByteString(beginSuffixIndex.toInt())
    source.skip(beginLineEndIndex + 1 - beginSuffixIndex) // skip suffix & new line

    val endIndex = source.indexOf(END_BYTES)
    if (endIndex == -1L) error("Invalid PEM format: missing END label")

    val base64Content = source.readByteString(endIndex.toInt())
    source.skip(END_BYTES.size.toLong())

    val endLineEndIndex = source.indexOf(NEW_LINE_BYTE)
    val endSuffixIndex = source.indexOf(SUFFIX_BYTES)
    if (endSuffixIndex == -1L || (endLineEndIndex != -1L && endSuffixIndex > endLineEndIndex)) error("Invalid PEM format: missing END label suffix")

    val endLabel = source.readByteString(endSuffixIndex.toInt())
    if (endLineEndIndex == -1L) {
        source.skip(SUFFIX_BYTES.size.toLong())
    } else {
        source.skip(endLineEndIndex + 1 - endSuffixIndex)
    }

    if (endLabel != beginLabel) error("Invalid PEM format: BEGIN=`${beginLabel.decodeToString()}`, END=`${endLabel.decodeToString()}`")

    return PemDocument(
        label = PemLabel(beginLabel.decodeToString()),
        content = Base64.Pem.decodeToByteString(base64Content)
    )
}
