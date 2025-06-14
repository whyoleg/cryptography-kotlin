/*
 * Copyright (c) 2025 Oleg Yukhnevich. Use of this source code is governed by the Apache 2.0 license.
 */

package dev.whyoleg.cryptography.providers.jdk

import dev.whyoleg.cryptography.*
import kotlin.test.*

class DefaultJdkSecurityProviderTest {
    @Test
    fun testProviderName() {
        // no security provider by default
        assertEquals(CryptographyProvider.JDK.name, "JDK")
    }
}
