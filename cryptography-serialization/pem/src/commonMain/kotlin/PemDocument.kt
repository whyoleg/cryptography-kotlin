/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.pem

import kotlinx.io.*
import kotlinx.io.bytestring.*
import kotlin.io.encoding.*

public class PemDocument(
    public val label: PemLabel,
    public val content: ByteString,
) {
    public constructor(
        label: PemLabel,
        content: ByteArray,
    ) : this(label, ByteString(content))

    public fun encodeToString(): String = buildString {
        encodedLines().forEach(::appendLine)
    }

    public fun encodeToByteArray(): ByteArray = encodeToString().encodeToByteArray()
    public fun encodeToByteString(): ByteString = encodeToString().encodeToByteString()

    public fun encodeToSink(sink: Sink) {
        encodedLines().forEach { line ->
            sink.writeString(line)
            sink.writeCodePointValue('\n'.code)
        }
    }

    // TODO: let's change implementation to use Base64.encodeToByteArray for Sink - there is no need to go through String
    //  same for encodeToByteString/encodeToByteArray
    private fun encodedLines(): Sequence<String> = sequence {
        yield(BEGIN_PREFIX + label.value + SUFFIX)
        yieldAll(Base64.encode(content).chunkedSequence(64))
        yield(END_PREFIX + label.value + SUFFIX)
    }

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
        private const val BEGIN_PREFIX = "-----BEGIN "
        private const val END_PREFIX = "-----END "
        private const val SUFFIX = "-----"

        // decode will skip comments and everything else which is not label or content

        // will decode only the first one, even if there is something else after it
        public fun decode(text: String): PemDocument = decode(text.lineSequence())
        public fun decode(bytes: ByteArray): PemDocument = decode(bytes.decodeToString().lineSequence())
        public fun decode(bytes: ByteString): PemDocument = decode(bytes.decodeToString().lineSequence())
        public fun decode(source: Source): PemDocument = decode(generateSequence(source::readLine))

        public fun decodeToSequence(text: String): Sequence<PemDocument> = decodeToSequence(text.lineSequence())
        public fun decodeToSequence(bytes: ByteArray): Sequence<PemDocument> = decodeToSequence(bytes.decodeToString().lineSequence())
        public fun decodeToSequence(bytes: ByteString): Sequence<PemDocument> = decodeToSequence(bytes.decodeToString().lineSequence())
        public fun decodeToSequence(source: Source): Sequence<PemDocument> = decodeToSequence(generateSequence(source::readLine))

        // implementation

        // it will never be empty
        private fun decode(lines: Sequence<String>): PemDocument = decodeToSequence(lines).first()

        // it will never be empty, or will throw an error - TBD
        private fun decodeToSequence(lines: Sequence<String>): Sequence<PemDocument> = sequence {
            var hasAtLeastOneBeginLabel = false
            var beginLabel: String? = null
            val content = StringBuilder()

            for (line in lines) {
                if (beginLabel == null) {
                    beginLabel = line.findLabel(BEGIN_PREFIX, "BEGIN") ?: continue
                    hasAtLeastOneBeginLabel = true
                } else {
                    val endLabel = line.findLabel(END_PREFIX, "END") ?: run {
                        content.append(line)
                        continue
                    }
                    check(beginLabel == endLabel) { "Invalid PEM format: BEGIN=`$beginLabel`, END=`$endLabel`" }

                    val document = PemDocument(
                        label = PemLabel(beginLabel),
                        content = Base64.decodeToByteString(content.toString())
                    )
                    content.clear()
                    beginLabel = null

                    yield(document)
                }
            }

            check(hasAtLeastOneBeginLabel) { "Invalid PEM format: missing BEGIN label" }
            check(beginLabel == null) { "Invalid PEM format: missing END label" }
        }

        private fun String.findLabel(prefix: String, type: String): String? {
            val startIndex = indexOf(prefix)
            if (startIndex == -1) return null

            val endIndex = lastIndexOf(SUFFIX)
            if (endIndex == -1) error("Invalid PEM format: missing suffix")

            val label = substring(startIndex + prefix.length, endIndex)
            if (label.isBlank()) error("Invalid PEM format: $type label is empty")

            return label
        }
    }
}
