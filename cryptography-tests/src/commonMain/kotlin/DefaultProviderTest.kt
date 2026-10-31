/*
 * Copyright (c) 2023-2026 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests

import dev.whyoleg.cryptography.*
import kotlin.test.*

// the tested provider is the only one in dependencies, so it must be the default one
abstract class DefaultProviderTest(private val provider: CryptographyProvider) {
    @Test
    fun default() {
        assertEquals(CryptographyProvider.Default.name, provider.name)
        assertEquals(CryptographyProvider.Default, provider)
    }
}
