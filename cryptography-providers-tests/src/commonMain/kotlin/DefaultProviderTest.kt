/*
 * Copyright (c) 2023-2024 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.tests

import dev.whyoleg.cryptography.*
import kotlin.test.*

abstract class DefaultProviderTest(private val provider: CryptographyProvider) {
    @Test
    fun test() {
        assertEquals(CryptographyProvider.Default.name, provider.name)
        assertEquals(CryptographyProvider.Default, provider)
    }
}
