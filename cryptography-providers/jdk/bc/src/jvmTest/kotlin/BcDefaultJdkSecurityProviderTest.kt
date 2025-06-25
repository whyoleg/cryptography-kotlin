/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk.bc

import dev.whyoleg.cryptography.*
import dev.whyoleg.cryptography.providers.jdk.*
import kotlin.test.*

class BcDefaultJdkSecurityProviderTest {
    @Test
    fun testProviderName() {
        assertEquals(CryptographyProvider.JDK.name, "JDK (BC)")
    }
}
