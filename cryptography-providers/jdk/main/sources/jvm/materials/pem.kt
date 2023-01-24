package dev.whyoleg.cryptography.jdk.materials

import java.util.*

internal fun ByteArray.encodeToPem(type: String): ByteArray =
    """
    |-----BEGIN $type-----
    |${Base64.getEncoder().encodeToString(this)}
    |-----END $type-----
    """.trimMargin().encodeToByteArray()

internal fun ByteArray.decodeFromPem(): Pair<String, ByteArray> {
    val lines = decodeToString().split("\n")
    check(lines.size >= 3) { "Invalid PEM format" }
    val headerType = lines.first().substringAfter("-----BEGIN ").substringBefore("-----").trim()
    val footerType = lines.last().substringAfter("-----END ").substringBefore("-----").trim()

    check(headerType == footerType) { "Invalid PEM format, BEGIN type: `$headerType`, END type: `$footerType`" }
    return headerType to Base64.getDecoder().decode(lines.drop(1).dropLast(1).joinToString("\n"))
}
