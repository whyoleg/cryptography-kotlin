/*
 * Copyright (c) 2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.serialization.pem

import kotlinx.io.bytestring.*
import kotlin.io.encoding.*

@Deprecated("Renamed to Pem", ReplaceWith("Pem"), DeprecationLevel.ERROR)
public typealias PEM = Pem

@OptIn(ExperimentalEncodingApi::class)
public object Pem {
    private const val BEGIN_PREFIX = "-----BEGIN "
    private const val END_PREFIX = "-----END "
    private const val SUFFIX = "-----"

    public fun encodeToByteString(content: PemContent): ByteString = encode(content).encodeToByteString()
    public fun encodeToByteArray(content: PemContent): ByteArray = encode(content).encodeToByteArray()
    public fun encode(content: PemContent): String = buildString {
        append(BEGIN_PREFIX).append(content.label.representation).appendLine(SUFFIX)
        Base64.encode(content.bytes).chunked(64).joinTo(this, separator = "\n", postfix = "\n")
        append(END_PREFIX).append(content.label.representation).appendLine(SUFFIX)
    }

    public fun decode(byteString: ByteString): PemContent = decode(byteString.decodeToString())
    public fun decode(bytes: ByteArray): PemContent = decode(bytes.decodeToString())
    public fun decode(string: String): PemContent {
        val lines = string.split("\n")
        val beginLine = lines.indexOfFirst { it.startsWith(BEGIN_PREFIX) }
        check(beginLine != -1) { "Invalid PEM format: missing BEGIN label" }
        val endLine = lines.indexOfFirst { it.startsWith(END_PREFIX) }
        check(endLine != -1) { "Invalid PEM format: missing END label" }

        val beginLabel = lines[beginLine].substringAfter(BEGIN_PREFIX).substringBefore(SUFFIX).trim()
        check(beginLabel.isNotBlank()) { "Invalid PEM format: BEGIN label is empty" }
        val endLabel = lines[endLine].substringAfter(END_PREFIX).substringBefore(SUFFIX).trim()
        check(endLabel.isNotBlank()) { "Invalid PEM format: BEGIN label is empty" }

        check(beginLabel == endLabel) { "Invalid PEM format: BEGIN=`$beginLabel`, END=`$endLabel`" }

        val contentText = lines.subList(beginLine + 1, endLine).joinToString("")

        return PemContent(
            label = PemLabel(beginLabel),
            bytes = Base64.decode(contentText)
        )
    }
}
