/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.pem

import kotlinx.io.*
import kotlinx.io.bytestring.*
import kotlinx.io.bytestring.unsafe.*
import kotlin.io.encoding.*

/**
 * Represents a single PEM (Privacy-Enhanced Mail) document as defined by [RFC 7468](https://datatracker.ietf.org/doc/html/rfc7468),
 * consisting of a textual [label], and the binary [content] it encapsulates
 *
 * To encode the document into a PEM-encoded string use one of
 * [encodeToString], [encodeToByteArray], [encodeToByteString], or [encodeToSink] depending on the desired output type
 *
 * Encoding produces the canonical PEM form:
 *
 * ```text
 * -----BEGIN {label}-----
 * Base64-encoded {content} with line breaks every 64 characters
 * -----END {label}-----
 * ```
 *
 * Creation of document instances can be done using one of the following methods:
 *
 * - using constructor, accepting [label] and [content]
 * - using [PemDocument.decode] for decoding from a string or binary input
 * - using [PemDocument.decodeToSequence] for decoding multiple documents from a single string or binary input
 *
 * [PemDocument] is an **immutable**, **thread-safe** value object, with structural equality and hash code that uses both [label] and [content].
 *
 * @constructor Creates a new [PemDocument] with the provided [label] and [content]
 * @property label Case-sensitive encapsulation label (for example, `"CERTIFICATE"` or `"PRIVATE KEY"`)
 * @property content Raw binary payload (commonly DER or any arbitrary bytes) that is base64-armored when encoded to PEM
 */
public class PemDocument(
    public val label: PemLabel,
    public val content: ByteString,
) {
    /**
     * Creates a new [PemDocument] with the provided [label] and [content]
     */
    public constructor(
        label: PemLabel,
        content: ByteArray,
    ) : this(label, ByteString(content))

    /**
     * Encodes this document into a [String] in [PEM](https://datatracker.ietf.org/doc/html/rfc7468) format
     *
     * The output uses the form:
     *
     * ```text
     * -----BEGIN {label}-----
     * Base64-encoded {content} with line breaks every 64 characters
     * -----END {label}-----
     * ```
     *
     * @return the PEM-encoded string
     * @sample dev.whyoleg.cryptography.serialization.pem.PemSamples.encodeToString
     */
    public fun encodeToString(): String = encodeToByteArrayImpl().decodeToString()

    /**
     * Encodes this document into a [ByteArray] as a string in [PEM](https://datatracker.ietf.org/doc/html/rfc7468) format
     *
     * The output uses the form:
     *
     * ```text
     * -----BEGIN {label}-----
     * Base64-encoded {content} with line breaks every 64 characters
     * -----END {label}-----
     * ```
     *
     * @return the bytes representing PEM-encoded string
     * @sample dev.whyoleg.cryptography.serialization.pem.PemSamples.encodeToByteArray
     */
    public fun encodeToByteArray(): ByteArray = encodeToByteArrayImpl()

    /**
     * Encodes this document into a [ByteString] as a string in [PEM](https://datatracker.ietf.org/doc/html/rfc7468) format
     *
     * The output uses the form:
     *
     * ```text
     * -----BEGIN {label}-----
     * Base64-encoded {content} with line breaks every 64 characters
     * -----END {label}-----
     * ```
     *
     * @return the bytes representing PEM-encoded string
     * @sample dev.whyoleg.cryptography.serialization.pem.PemSamples.encodeToByteString
     */
    @OptIn(UnsafeByteStringApi::class)
    public fun encodeToByteString(): ByteString = UnsafeByteStringOperations.wrapUnsafe(encodeToByteArrayImpl())

    /**
     * Encodes this document to the provided [sink] as a string in [PEM](https://datatracker.ietf.org/doc/html/rfc7468) format
     *
     * The output uses the form:
     *
     * ```text
     * -----BEGIN {label}-----
     * Base64-encoded {content} with line breaks every 64 characters
     * -----END {label}-----
     * ```
     *
     * @param sink the destination to write bytes representing PEM-encoded string into
     * @sample dev.whyoleg.cryptography.serialization.pem.PemSamples.encodeToSink
     */
    public fun encodeToSink(sink: Sink): Unit = sink.write(encodeToByteArrayImpl())

    /**
     * Returns `true` if [other] is a [PemDocument] with the same [label] and [content]
     *
     * [content] should contain exactly the same byte sequence
     */
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PemDocument) return false

        if (label != other.label) return false
        if (content != other.content) return false

        return true
    }

    /**
     * Returns a hash code consistent with [equals], computed from [label] and [content]
     */
    override fun hashCode(): Int {
        var result = label.hashCode()
        result = 31 * result + content.hashCode()
        return result
    }

    /**
     * Returns a concise debug representation of this document including its [label] and [content]
     *
     * **Avoid logging if the [content] is sensitive**
     */
    override fun toString(): String {
        return "PemDocument(label=${label.value}, content=$content)"
    }

    public companion object {
        /**
         * Decodes the first [PEM](https://datatracker.ietf.org/doc/html/rfc7468) document found in [text]
         *
         * The input should be in the form:
         *
         * ```text
         * -----BEGIN {label}-----
         * Base64-encoded {content} with line breaks every 64 characters
         * -----END {label}-----
         * ```
         *
         * Any content before `-----BEGIN {label}-----` and after `-----END {label}-----` is ignored
         *
         * Only the first complete document is decoded. For decoding of multiple documents, use [PemDocument.decodeToSequence]
         *
         * @param text the textual input that may contain a PEM document
         * @return the decoded [PemDocument]
         * @throws IllegalArgumentException if no PEM documents present in [text], or the PEM encoding is invalid
         * @sample dev.whyoleg.cryptography.serialization.pem.PemSamples.decodeFromString
         */
        public fun decode(text: String): PemDocument {
            return tryDecodeFromString(text, startIndex = 0, saveEndIndex = {}) ?: throwPemMissingBeginLabel()
        }

        /**
         * Lazily decodes all [PEM](https://datatracker.ietf.org/doc/html/rfc7468) documents found in [text]
         *
         * The input should be in the form:
         *
         * ```text
         * -----BEGIN {LABEL1}-----
         * Base64-encoded {content} with line breaks every 64 characters
         * -----END {LABEL1}-----
         *
         * -----BEGIN {LABEL2}-----
         * Base64-encoded {content} with line breaks every 64 characters
         * -----END {LABEL2}-----
         * ```
         *
         * Any content before the first `-----BEGIN {label}-----` and after the last `-----END {label}-----` is ignored,
         * as well as any content after each document and before the next `-----BEGIN {label}-----`.
         * The sequence yields each discovered [PemDocument] in order
         *
         * @param text the textual input that may contain multiple PEM documents
         * @return a sequence of decoded [PemDocument]s, empty sequence if no PEM documents present
         * @throws IllegalArgumentException if the PEM encoding of any document is invalid
         * @sample dev.whyoleg.cryptography.serialization.pem.PemSamples.decodeToSequenceFromString
         */
        public fun decodeToSequence(text: String): Sequence<PemDocument> = sequence {
            var startIndex = 0
            while (startIndex < text.length) {
                yield(tryDecodeFromString(text, startIndex) { startIndex = it } ?: break)
            }
        }

        /**
         * Decodes the first [PEM](https://datatracker.ietf.org/doc/html/rfc7468) document found in [bytes].
         * The [bytes] are treated as an encoded string
         *
         * The input should be in the form:
         *
         * ```text
         * -----BEGIN {label}-----
         * Base64-encoded {content} with line breaks every 64 characters
         * -----END {label}-----
         * ```
         *
         * Any content before `-----BEGIN {label}-----` and after `-----END {label}-----` is ignored
         *
         * Only the first complete document is decoded. For decoding of multiple documents, use [PemDocument.decodeToSequence]
         *
         * @param bytes the byte array that may contain a PEM document
         * @return the decoded [PemDocument]
         * @throws IllegalArgumentException if no PEM documents present in [bytes], or the PEM encoding is invalid
         * @sample dev.whyoleg.cryptography.serialization.pem.PemSamples.decodeFromByteArray
         */
        @OptIn(UnsafeByteStringApi::class)
        public fun decode(bytes: ByteArray): PemDocument {
            return decode(UnsafeByteStringOperations.wrapUnsafe(bytes))
        }

        /**
         * Lazily decodes all [PEM](https://datatracker.ietf.org/doc/html/rfc7468) documents found in [bytes].
         * The [bytes] are treated as an encoded string
         *
         * The input should be in the form:
         *
         * ```text
         * -----BEGIN {LABEL1}-----
         * Base64-encoded {content} with line breaks every 64 characters
         * -----END {LABEL1}-----
         *
         * -----BEGIN {LABEL2}-----
         * Base64-encoded {content} with line breaks every 64 characters
         * -----END {LABEL2}-----
         * ```
         *
         * Any content before the first `-----BEGIN {label}-----` and after the last `-----END {label}-----` is ignored,
         * as well as any content after each document and before the next `-----BEGIN {label}-----`.
         * The sequence yields each discovered [PemDocument] in order
         *
         * @param bytes the byte array that may contain multiple PEM documents
         * @return a sequence of decoded [PemDocument]s, empty sequence if no PEM documents present
         * @throws IllegalArgumentException if the PEM encoding of any document is invalid
         * @sample dev.whyoleg.cryptography.serialization.pem.PemSamples.decodeToSequenceFromByteArray
         */
        @OptIn(UnsafeByteStringApi::class)
        public fun decodeToSequence(bytes: ByteArray): Sequence<PemDocument> {
            return decodeToSequence(UnsafeByteStringOperations.wrapUnsafe(bytes))
        }

        /**
         * Decodes the first [PEM](https://datatracker.ietf.org/doc/html/rfc7468) document found in [bytes].
         * The [bytes] are treated as an encoded string
         *
         * The input should be in the form:
         *
         * ```text
         * -----BEGIN {label}-----
         * Base64-encoded {content} with line breaks every 64 characters
         * -----END {label}-----
         * ```
         *
         * Any content before `-----BEGIN {label}-----` and after `-----END {label}-----` is ignored
         *
         * Only the first complete document is decoded. For decoding of multiple documents, use [PemDocument.decodeToSequence]
         *
         * @param bytes the byte array that may contain a PEM document
         * @return the decoded [PemDocument]
         * @throws IllegalArgumentException if no PEM documents present in [bytes], or the PEM encoding is invalid
         * @sample dev.whyoleg.cryptography.serialization.pem.PemSamples.decodeFromByteString
         */
        public fun decode(bytes: ByteString): PemDocument {
            return tryDecodeFromByteString(bytes, startIndex = 0, saveEndIndex = {}) ?: throwPemMissingBeginLabel()
        }

        /**
         * Lazily decodes all [PEM](https://datatracker.ietf.org/doc/html/rfc7468) documents found in [bytes].
         * The [bytes] are treated as an encoded string
         *
         * The input should be in the form:
         *
         * ```text
         * -----BEGIN {LABEL1}-----
         * Base64-encoded {content} with line breaks every 64 characters
         * -----END {LABEL1}-----
         *
         * -----BEGIN {LABEL2}-----
         * Base64-encoded {content} with line breaks every 64 characters
         * -----END {LABEL2}-----
         * ```
         *
         * Any content before the first `-----BEGIN {label}-----` and after the last `-----END {label}-----` is ignored,
         * as well as any content after each document and before the next `-----BEGIN {label}-----`.
         * The sequence yields each discovered [PemDocument] in order
         *
         * @param bytes the byte array that may contain multiple PEM documents
         * @return a sequence of decoded [PemDocument]s, empty sequence if no PEM documents present
         * @throws IllegalArgumentException if the PEM encoding of any document is invalid
         * @sample dev.whyoleg.cryptography.serialization.pem.PemSamples.decodeToSequenceFromByteString
         */
        public fun decodeToSequence(bytes: ByteString): Sequence<PemDocument> = sequence {
            var startIndex = 0
            while (startIndex < bytes.size) {
                yield(tryDecodeFromByteString(bytes, startIndex) { startIndex = it } ?: break)
            }
        }

        /**
         * Decodes the first [PEM](https://datatracker.ietf.org/doc/html/rfc7468) document found in [source].
         * The [source] is treated as an encoded string and is consumed up to and including the decoded document
         *
         *
         * The input should be in the form:
         *
         * ```text
         * -----BEGIN {label}-----
         * Base64-encoded {content} with line breaks every 64 characters
         * -----END {label}-----
         * ```
         *
         * Any content before `-----BEGIN {label}-----` and after `-----END {label}-----` is ignored
         *
         * Only the first complete document is decoded. For decoding of multiple documents, use [PemDocument.decodeToSequence]
         *
         * @param source the source to read from
         * @return the decoded [PemDocument]
         * @throws IllegalArgumentException if no PEM documents present in [source], or the PEM encoding is invalid
         * @sample dev.whyoleg.cryptography.serialization.pem.PemSamples.decodeFromSource
         */
        public fun decode(source: Source): PemDocument {
            return tryDecodeFromSource(source) ?: throwPemMissingBeginLabel()
        }

        /**
         * Lazily decodes all [PEM](https://datatracker.ietf.org/doc/html/rfc7468) documents found in [source].
         * The [source] is treated as an encoded string and is consumed up to and including the last decoded document, which was consumed from the sequence
         *
         * The input should be in the form:
         *
         * ```text
         * -----BEGIN {LABEL1}-----
         * Base64-encoded {content} with line breaks every 64 characters
         * -----END {LABEL1}-----
         *
         * -----BEGIN {LABEL2}-----
         * Base64-encoded {content} with line breaks every 64 characters
         * -----END {LABEL2}-----
         * ```
         *
         * Any content before the first `-----BEGIN {label}-----` and after the last `-----END {label}-----` is ignored,
         * as well as any content after each document and before the next `-----BEGIN {label}-----`.
         * The sequence yields each discovered [PemDocument] in order
         *
         * @param source the source to read from
         * @return a sequence of decoded [PemDocument]s, empty sequence if no PEM documents present
         * @throws IllegalArgumentException if the PEM encoding of any document is invalid
         * @sample dev.whyoleg.cryptography.serialization.pem.PemSamples.decodeToSequenceFromSource
         */
        public fun decodeToSequence(source: Source): Sequence<PemDocument> = sequence {
            while (!source.exhausted()) {
                yield(tryDecodeFromSource(source) ?: break)
            }
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
    if (beginLineEndIndex == -1) throwPemMissingNewLineAfterBeginLabel()
    val beginSuffixIndex = text.indexOf(SUFFIX, beginIndex + BEGIN_PREFIX.length)
    if (beginSuffixIndex == -1 || beginSuffixIndex > beginLineEndIndex) throwPemMissingBeginLabelSuffix()

    val beginLabel = text.substring(beginIndex + BEGIN_PREFIX.length, beginSuffixIndex)

    val endIndex = text.indexOf(END_PREFIX, beginLineEndIndex)
    if (endIndex == -1) throwPemMissingEndLabel()
    val endLineEndIndex = text.indexOf(NEW_LINE, endIndex + END_PREFIX.length)
    val endSuffixIndex = text.indexOf(SUFFIX, endIndex + END_PREFIX.length)
    if (endSuffixIndex == -1 || (endLineEndIndex != -1 && endSuffixIndex > endLineEndIndex)) throwPemMissingEndLabelSuffix()

    val endLabel = text.substring(endIndex + END_PREFIX.length, endSuffixIndex)
    if (endLabel != beginLabel) throwPemBeginEndLabelMismatch(beginLabel, endLabel)

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
    if (beginLineEndIndex == -1) throwPemMissingNewLineAfterBeginLabel()
    val beginSuffixIndex = bytes.indexOf(SUFFIX_BYTES, beginIndex + BEGIN_BYTES.size)
    if (beginSuffixIndex == -1 || beginSuffixIndex > beginLineEndIndex) throwPemMissingBeginLabelSuffix()

    val beginLabel = bytes.substring(beginIndex + BEGIN_BYTES.size, beginSuffixIndex)

    val endIndex = bytes.indexOf(END_BYTES, beginLineEndIndex)
    if (endIndex == -1) throwPemMissingEndLabel()
    val endLineEndIndex = bytes.indexOf(NEW_LINE_BYTE, endIndex + END_BYTES.size)
    val endSuffixIndex = bytes.indexOf(SUFFIX_BYTES, endIndex + END_BYTES.size)
    if (endSuffixIndex == -1 || (endLineEndIndex != -1 && endSuffixIndex > endLineEndIndex)) throwPemMissingEndLabelSuffix()

    val endLabel = bytes.substring(endIndex + END_BYTES.size, endSuffixIndex)
    if (endLabel != beginLabel) throwPemBeginEndLabelMismatch(beginLabel.decodeToString(), endLabel.decodeToString())

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
    if (beginLineEndIndex == -1L) throwPemMissingNewLineAfterBeginLabel()
    val beginSuffixIndex = source.indexOf(SUFFIX_BYTES)
    if (beginSuffixIndex == -1L || beginSuffixIndex > beginLineEndIndex) throwPemMissingBeginLabelSuffix()

    val beginLabel = source.readByteString(beginSuffixIndex.toInt())
    source.skip(beginLineEndIndex + 1 - beginSuffixIndex) // skip suffix & new line

    val endIndex = source.indexOf(END_BYTES)
    if (endIndex == -1L) throwPemMissingEndLabel()

    val base64Content = source.readByteString(endIndex.toInt())
    source.skip(END_BYTES.size.toLong())

    val endLineEndIndex = source.indexOf(NEW_LINE_BYTE)
    val endSuffixIndex = source.indexOf(SUFFIX_BYTES)
    if (endSuffixIndex == -1L || (endLineEndIndex != -1L && endSuffixIndex > endLineEndIndex)) throwPemMissingEndLabelSuffix()

    val endLabel = source.readByteString(endSuffixIndex.toInt())
    if (endLineEndIndex == -1L) {
        source.skip(SUFFIX_BYTES.size.toLong())
    } else {
        source.skip(endLineEndIndex + 1 - endSuffixIndex)
    }

    if (endLabel != beginLabel) throwPemBeginEndLabelMismatch(beginLabel.decodeToString(), endLabel.decodeToString())

    return PemDocument(
        label = PemLabel(beginLabel.decodeToString()),
        content = Base64.Pem.decodeToByteString(base64Content)
    )
}

private fun throwPemInvalid(message: String): Nothing = throw IllegalArgumentException("Invalid PEM format: $message")
private fun throwPemMissingBeginLabel(): Nothing = throwPemInvalid("missing BEGIN label")
private fun throwPemMissingNewLineAfterBeginLabel(): Nothing = throwPemInvalid("missing new line after BEGIN label")
private fun throwPemMissingBeginLabelSuffix(): Nothing = throwPemInvalid("missing BEGIN label suffix")
private fun throwPemMissingEndLabel(): Nothing = throwPemInvalid("missing END label")
private fun throwPemMissingEndLabelSuffix(): Nothing = throwPemInvalid("missing END label suffix")
private fun throwPemBeginEndLabelMismatch(beginLabel: String, endLabel: String): Nothing =
    throwPemInvalid("BEGIN($beginLabel) and END($endLabel) labels mismatch")
