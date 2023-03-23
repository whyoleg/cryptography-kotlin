/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import dev.whyoleg.cryptography.algorithms.digest.*
import dev.whyoleg.cryptography.provider.*
import kotlinx.coroutines.*
import kotlinx.coroutines.test.*
import kotlin.test.*

class JustTest {

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun test() = runTest {
        val digest =
            CryptographyProvider.Default
                .get(SHA256)
                .hasher()
                .hash("Hello World".encodeToByteArray())
                .let(::printHexBinary)

        assertEquals("a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e", digest)
    }
}

private const val hexCode = "0123456789ABCDEF"
internal fun printHexBinary(data: ByteArray): String {
    val r = StringBuilder(data.size * 2)
    for (b in data) {
        r.append(hexCode[b.toInt() shr 4 and 0xF])
        r.append(hexCode[b.toInt() and 0xF])
    }
    return r.toString().lowercase()
}
