/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.algorithms.*
import kotlinx.coroutines.test.*
import kotlin.test.*

class JustTest {

    @OptIn(ExperimentalStdlibApi::class)
    @Test
    fun test() = runTest {
        val digest =
            CryptographyProvider.Default
                .get(SHA256)
                .hasher()
                .hash("Hello World".encodeToByteArray())
                .toHexString()

        assertEquals("a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e", digest)
    }
}
