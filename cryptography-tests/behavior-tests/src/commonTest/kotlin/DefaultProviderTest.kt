/*
 * Copyright (c) 2023 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.tests.behavior

import dev.whyoleg.cryptography.provider.*
import dev.whyoleg.cryptography.test.utils.*
import kotlin.test.*

class DefaultProviderTest {
    @Test
    fun test() {
        val defaultName = CryptographyProvider.Default.name
        assertContains(availableProviders.map { it.name }, defaultName)
    }
}
