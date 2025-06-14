/*
 * Copyright (c) 2023-2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.optimal

import dev.whyoleg.cryptography.*
import kotlin.test.*

class RegisteredProvidersTest {
    @Test
    fun test() {
        assertTrue(CryptographySystem.getRegisteredProviders().also {
            println(it)
        }.isNotEmpty())
    }
}
