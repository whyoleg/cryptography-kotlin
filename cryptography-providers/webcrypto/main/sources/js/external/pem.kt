package dev.whyoleg.cryptography.webcrypto.external

import org.khronos.webgl.*

private const val BEGIN_PREFIX = "-----BEGIN "
private const val END_PREFIX = "-----END "
private const val SUFFIX = "-----"

internal fun ArrayBuffer.encodeToPem(type: String): ByteArray = buildString {
    append(BEGIN_PREFIX).append(type).append(SUFFIX)
    encodeBase64(this@encodeToPem).chunked(64).joinTo(this, "\n", "\n", "\n")
    append(END_PREFIX).append(type).append(SUFFIX)
    append("\n")
}.encodeToByteArray()

internal fun ByteArray.decodeFromPem(type: String): ByteArray {
    val lines = decodeToString().split("\n").filter { it.isNotBlank() }
    check(lines.size >= 3) { "Invalid PEM format" }
    val headerType = lines.first().substringAfter(BEGIN_PREFIX).substringBefore(SUFFIX).trim()
    val footerType = lines.last().substringAfter(END_PREFIX).substringBefore(SUFFIX).trim()

    check(headerType == footerType) { "Invalid PEM format, BEGIN type: `$headerType`, END type: `$footerType`" }
    check(headerType == type) { "Wrong PEM type, expected $type, actual $headerType" }
    return decodeBase64(lines.drop(1).dropLast(1).joinToString(""))
}
