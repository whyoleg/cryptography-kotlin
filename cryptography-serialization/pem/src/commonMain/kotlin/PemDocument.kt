/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.pem

import kotlinx.io.*
import kotlinx.io.bytestring.*
import kotlin.io.encoding.*

@OptIn(ExperimentalEncodingApi::class)
public class PemDocument internal constructor(
    public val label: PemLabel,
    public val content: ByteString,
) {
    // TODO: this could be optimized :)
    public fun encodeToString(): String = buildString {
        encodeLines().forEach { appendLine(it) }
//        append(BEGIN_PREFIX).append(label.value).appendLine(SUFFIX)
//        Base64.Default.encode(bytes).chunked(64).joinTo(this, separator = "\n", postfix = "\n")
//        append(END_PREFIX).append(label.value).appendLine(SUFFIX)
    }

    // TODO: this could be optimized :)
    public fun encodeToSink(sink: Sink) {
        encodeLines().forEach {
            sink.writeString(it)
            sink.writeCodePointValue('\n'.code)
        }
        sink.writeString(encodeToString())
    }

    private fun encodeLines(): Sequence<String> = sequence {
        yield(BEGIN_PREFIX + label.value + SUFFIX)
        yieldAll(Base64.Default.encode(content).chunked(64))
        yield(END_PREFIX + label.value + SUFFIX)
    }

    public companion object {
        private const val BEGIN_PREFIX = "-----BEGIN "
        private const val END_PREFIX = "-----END "
        private const val SUFFIX = "-----"

        // will skip comments
        // will decode only the first one, even if there is something else after it
        public fun decode(text: String): PemDocument = decode(text.lineSequence())
        public fun decode(source: Source): PemDocument = decode(generateSequence(source::readLine))

        public fun decodeToSequence(text: String): Sequence<PemDocument> = decodeToSequence(text.lineSequence())
        public fun decodeToSequence(source: Source): Sequence<PemDocument> = decodeToSequence(generateSequence(source::readLine))

        private fun decode(lines: Sequence<String>): PemDocument {
            return decodeToSequence(lines).first() // it will never be empty
        }

        // TODO: recheck :)
        // it will never be empty, or will throw an error - TBD
        private fun decodeToSequence(lines: Sequence<String>): Sequence<PemDocument> = sequence {
            var hasAtLeastOneBeginLabel = false
            var beginLabel: String? = null
            val content = StringBuilder()

            for (line in lines) {
                if (beginLabel == null) {
                    if (line.startsWith(BEGIN_PREFIX)) {
                        hasAtLeastOneBeginLabel = true
                        beginLabel = line.substringAfter(BEGIN_PREFIX).substringBefore(SUFFIX).trim()
                        check(beginLabel.isNotBlank()) { "Invalid PEM format: BEGIN label is empty" }
                    }
                } else {
                    if (line.startsWith(END_PREFIX)) {
                        val endLabel = line.substringAfter(END_PREFIX).substringBefore(SUFFIX).trim()
                        check(endLabel.isNotBlank()) { "Invalid PEM format: BEGIN label is empty" }

                        check(beginLabel == endLabel) { "Invalid PEM format: BEGIN=`$beginLabel`, END=`$endLabel`" }
                        val document = PemDocument(
                            label = PemLabel(beginLabel),
                            content = Base64.Default.decodeToByteString(content.toString())
                        )
                        content.clear()
                        beginLabel = null

                        yield(document)
                    } else {
                        content.append(line)
                    }
                }
            }
            check(hasAtLeastOneBeginLabel) { "Invalid PEM format: missing BEGIN label" }
            check(beginLabel == null) { "Invalid PEM format: missing END label" }
        }
    }
}
