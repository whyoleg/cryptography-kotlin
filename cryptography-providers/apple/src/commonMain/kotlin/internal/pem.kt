/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.apple.internal

import kotlinx.cinterop.*
import platform.Foundation.*

private const val BEGIN_PREFIX = "-----BEGIN "
private const val END_PREFIX = "-----END "
private const val SUFFIX = "-----"

@OptIn(UnsafeNumber::class)
internal fun NSData.encodeToPem(type: String): ByteArray = buildString {
    append(BEGIN_PREFIX).append(type).appendLine(SUFFIX)
    appendLine(base64EncodedStringWithOptions(NSDataBase64Encoding64CharacterLineLength or NSDataBase64EncodingEndLineWithLineFeed))
    append(END_PREFIX).append(type).append(SUFFIX)
    append("\n")
}.encodeToByteArray()

@OptIn(UnsafeNumber::class, BetaInteropApi::class)
internal fun ByteArray.decodeFromPem(type: String): NSData? {
    val lines = decodeToString().split("\n").filter { it.isNotBlank() }
    check(lines.size >= 3) { "Invalid PEM format" }
    val headerType = lines.first().substringAfter(BEGIN_PREFIX).substringBefore(SUFFIX).trim()
    val footerType = lines.last().substringAfter(END_PREFIX).substringBefore(SUFFIX).trim()

    check(headerType == footerType) { "Invalid PEM format, BEGIN type: `$headerType`, END type: `$footerType`" }
    check(headerType == type) { "Wrong PEM type, expected $type, actual $headerType" }
    return NSData.create(
        base64EncodedString = lines.drop(1).dropLast(1).joinToString(""),
        options = 0.convert()
    )
}
