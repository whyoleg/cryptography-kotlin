/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.digest.*

private val Sha256 = CryptographyProvider.Default.get(SHA256).hasher()

suspend fun sha256(input: String): String {
    val bytes = input.encodeToByteArray()
    val digest = Sha256.hash(bytes)
    return digest.toHex()
}

private const val HEX = "0123456789ABCDEF"
private fun ByteArray.toHex(): String {
    return buildString(size * 2) {
        this@toHex.forEach {
            append(HEX[it.toInt() shr 4 and 0xF])
            append(HEX[it.toInt() and 0xF])
        }
    }.lowercase()
}
